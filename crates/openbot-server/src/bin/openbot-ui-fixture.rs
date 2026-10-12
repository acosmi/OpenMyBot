//! Local-only deterministic GUI fixture host required by the GUI first-source golden workflow.

#[path = "ui_fixture/credentials.rs"]
mod fixture_credentials;
#[path = "ui_fixture/model_connections.rs"]
mod fixture_model_connections;
#[path = "ui_fixture/plugins.rs"]
mod fixture_plugins;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use axum::response::IntoResponse as _;
use futures_core::Stream;
use openbot_application::cursor::ChannelCursor;
use openbot_application::{
    AgentAdministration, AgentAdministrationError, AgentAdministrationScope,
    AgentCallbackTokenAdministration, AgentCallbackTokenError, AgentDirectory, AgentReachability,
    AgentReadScope, AppEventStream, ApplicationService, AuditPageRequest, AuditReadError,
    AuditReader, BeginThreadRunRequest, CancelThreadRunRequest, ChannelAdministration,
    ChannelAdministrationError, ChannelCreateRequest, ChannelReadScope, ChannelReader,
    ChannelRoutingBackend, ChannelRoutingBackendError, ComponentAdministration,
    ComponentAdministrationError, ComponentFunctionArguments, ComponentFunctionCallPlan,
    ComponentRuntimeScope, CorrectMemoryRequest, McpConnectionAdministration, McpConnectionError,
    MemoryAdministration, MemoryAdministrationError, MemoryControlRequest, MemoryPageRequest,
    MutateMemoryRequest, OpenBotApplication, PeopleAdministration, PeoplePageRequest,
    PeoplePortError, PortError, RecallMemoriesRequest, RememberMemoryRequest, RoutingAuditRecord,
    SandboxedComponentAdministration, SandboxedComponentAdministrationError,
    SandboxedComponentDraft, ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError,
    ThreadEventSubscription, ThreadHistoryRequest, ToolApprovalAdministration,
    ToolApprovalAdministrationError, ToolApprovalPresentation, ToolApprovalRequest,
    UiPreferenceAdministration, UiPreferenceAdministrationError, UpdateMemoryControlRequest,
};
use openbot_contracts::agent::{
    AgentConnectionTestRequest, AgentConnectionVerdict, AgentLifecycleReceipt, AgentLifecycleState,
    AgentMutationRequest, AgentProfile, AgentVisibility, CallbackTokenIssued, CallbackTokenRevoked,
};
use openbot_contracts::audit::{AuditEventView, AuditPage};
use openbot_contracts::auth::{
    ApplicationRuntimeMode, AuthContext, AuthGeneration, AuthProviderId,
    AuthenticationCapabilities, EnterpriseSsoRoutingAccepted, Role,
};
use openbot_contracts::command::{
    AppEvent, ChannelActivityEvent, ChannelDetail, ChannelSummary, ThreadConversationSnapshot,
    ThreadForegroundRunState, ThreadHistory, ThreadHistoryMessage, ThreadHistoryRole,
    ThreadRunAnchor, ThreadRunCancellation, ThreadRunCancellationState, ThreadRunEvent,
    ThreadRunEventKind, ThreadRunStarted,
};
use openbot_contracts::components::{
    ASK_APPROVAL_COMPONENT_NAME, ASK_CHOICE_COMPONENT_NAME, BOT_ACTIVITY_FUNCTION_NAME,
    BotActivityReport, BotActivityRow, CompiledComponentKind, CompiledComponentManifestEntry,
    ComponentCatalogueAdded, ComponentFunctionCall, ComponentFunctionData,
    ComponentGovernanceMutation, ComponentHumanDecisionAnswer, ComponentHumanDecisionResolved,
    ComponentRecord, ComponentRecords, PendingComponentHumanDecision,
    PendingComponentHumanDecisions, RECENT_REFUSALS_FUNCTION_NAME, RecentRefusalRow,
    RecentRefusalsReport, SHOW_ACTIVITY_REPORT_COMPONENT_NAME,
    validate_component_human_decision_answer,
};
use openbot_contracts::error::IdentityConflictReason;
use openbot_contracts::ids::{
    ActorId, AuditEventId, BotId, CatalogGeneration, ChannelId, ComputerGeneration, DeploymentId,
    RunId, TenantId, ThreadId, ToolCallId,
};
use openbot_contracts::mcp::{
    McpConnection, McpConnectionDisconnected, McpConnections, McpOAuthAuthorization,
    McpOAuthClientRegistered, McpOAuthClientRegistration, McpOAuthReturnTo,
    McpVendorRevocationStatus,
};
use openbot_contracts::memory::{
    MemoryControl, MemoryKind, MemoryMutation, MemoryOrigin, MemoryPage, MemoryRecall,
    MemoryRecord, MemoryScope, MemorySensitivity, MemorySource, MemoryStatus,
};
use openbot_contracts::people::{CurrentUser, PeoplePage, Person};
use openbot_contracts::sandboxed::{
    PublishedSandboxedComponent, PublishedSandboxedComponents, SandboxedComponentRecord,
    SandboxedComponents,
};
use openbot_contracts::tool::{
    PendingToolApproval, PendingToolApprovals, ToolApprovalActivityEvent, ToolApprovalClass,
    ToolApprovalDecision, ToolApprovalEffect, ToolApprovalResolved,
};
use openbot_contracts::ui::{UiPreferences, UpdateUiPreferences};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::identity::roles::AdminFloor;
use openbot_domain::identity::session::{
    SessionHashKey, SessionState, SessionToken, SessionTokenHash, TrustedOrigins, evaluate_session,
};
use openbot_domain::tool::approval::{ApprovalTarget, PolicyVersionTag};
use openbot_domain::tool::metadata::{ApprovalClass, Effect, ToolName};
use openbot_domain::vault::{KeyVersion, WrappingKey};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::sso::DynamicSsoService;
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::net::safe_http::{EgressPolicy, SafeDialer};
use openbot_infra::policy::PolicyStore;
use openbot_infra::repo::people_admin::PostgresPeopleAdministration;
use openbot_infra::tool_approval::{DurableHumanDecision, PostgresToolApprovalCoordinator};
use openbot_server::auth::SESSION_COOKIE_NAME;
use openbot_server::{
    AuthResolver, PostgresSessionAuthResolver, ResolvedAuth, SensitiveWriteSecurity, ServerBuilder,
    StaticApp,
};
use time::{Duration, OffsetDateTime};

const FIXTURE_EXISTING_THREAD: &str = "550e8400-e29b-81d4-a716-446655440000";
const FIXTURE_APPROVAL_THREAD: &str = "550e8400-e29b-81d4-a716-446655440001";
const FIXTURE_CHOICE_THREAD: &str = "550e8400-e29b-81d4-a716-446655440002";
const FIXTURE_APPROVAL_RUN: &str = "fixture-decision-run-approval";
const FIXTURE_CHOICE_RUN: &str = "fixture-decision-run-choice";
const FIXTURE_GOOGLE_DRIVE_SERVER: &str = "google-drive";
const FIXTURE_GOOGLE_DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.readonly";
const FIXTURE_ACTIVITY_FOLLOW_UP: &str =
    "What has bot-busiest actually been doing? Look at the audit trail and summarise it.";
const FIXTURE_ROUTING_FALLBACK_CANARY: &str = "fixture routing fallback";
const FIXTURE_DEPLOYMENT: &str = "fixture-deployment";
const FIXTURE_TENANT: &str = "fixture-tenant";
const FIXTURE_ACTOR: &str = "fixture-actor";
const FIXTURE_PG_BOT: &str = "fixture-pg-approval-bot";
const FIXTURE_PG_THREAD: &str = "fixture-pg-approval-thread";
const FIXTURE_PG_RUN: &str = "fixture-pg-approval-run";
const FIXTURE_PG_CALL: &str = "fixture-pg-approval-call";
const FIXTURE_APPROVAL_DATABASE_URL: &str = "OPENBOT_UI_APPROVAL_DATABASE_URL";
const FIXTURE_AUTH_JOURNEY_ENV: &str = "OPENBOT_UI_AUTH_FIXTURE";
const FIXTURE_HOME_SKILLS_ENV: &str = "OPENBOT_UI_HOME_SKILLS_FIXTURE";
const FIXTURE_APPROVAL_DATABASE_PREFIX: &str = "openbot_ui_approval_fixture_";
const FIXTURE_APPROVAL_AUDIT_KEY: &[u8] = b"fixture-approval-audit-key-at-least-32";
const FIXTURE_SESSION_ID: &str = "fixture-pg-session";
const FIXTURE_SESSION_TOKEN: &str = "fixture-pg-session-token-with-enough-entropy-001";
const FIXTURE_SESSION_HASH_KEY: &[u8] = b"fixture-session-hash-key-at-least-32";
const FIXTURE_CONFIGURED_ADMIN_EMAIL: &str = "configured-admin@example.test";
const FIXTURE_SSO_PUBLIC_URL: &str = "https://fixture.openbot.test";
const FIXTURE_SSO_ROUTE_COOKIE: &str = "openbot_sso_route=fixture-auth-route";
const POSTGRES_APPROVAL_SEED_SQL: &str = "INSERT INTO public.users(id,email,auth_generation) VALUES
       ('fixture-actor','fixture-actor@example.test',1);
     INSERT INTO public.users(id,email,name,auth_generation) VALUES
       ('fixture-target','target@example.test','Target Person',0),
       ('fixture-configured-admin','configured-admin@example.test','Configured Administrator',0);
     INSERT INTO public.user_roles(user_id,role) VALUES
       ('fixture-actor','user'),('fixture-actor','admin'),
       ('fixture-target','user'),('fixture-configured-admin','admin');
     INSERT INTO public.action_policy(id,mode,deny,allow,updated_by) VALUES
       ('current','enforce','{}',ARRAY['actor.id == \"fixture-actor\"'],'fixture-seed');
     INSERT INTO public.agents(id,name,type,configuration)
       VALUES('fixture-pg-approval-bot','Fixture Approval Bot','built_in','{}');
     INSERT INTO public.agent_profiles(
       agent_id,owner_user_id,title,role_description,avatar_seed,visibility
     ) VALUES(
       'fixture-pg-approval-bot',NULL,'Fixture Approval Bot','role','seed','public'
     );
     INSERT INTO public.threads(
       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status
     ) VALUES(
       'fixture-pg-approval-thread','fixture-tenant','fixture-deployment',
       'fixture-actor','direct_bot','fixture-pg-approval-bot','active'
     );
     INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
       ('fixture-pg-approval-thread','fixture-actor');
     INSERT INTO public.runs(
       run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,started_at
     ) VALUES(
       'fixture-pg-approval-run','fixture-pg-approval-thread',
       'fixture-pg-approval-bot','fixture-actor',true,'running',1,clock_timestamp()
     );
     INSERT INTO public.thread_leases(
       thread_id,owner_id,fencing_token,acquired_at,expires_at,updated_at
     ) VALUES(
       'fixture-pg-approval-thread','fixture-runtime',1,clock_timestamp(),
       clock_timestamp()+interval '10 minutes',clock_timestamp()
     );";

#[derive(Clone, Default)]
struct AuthJourneyProbe {
    me_requests: Arc<AtomicU64>,
    capability_requests: Arc<AtomicU64>,
    oidc_start_requests: Arc<AtomicU64>,
    enterprise_start_requests: Arc<AtomicU64>,
    enterprise_continue_requests: Arc<AtomicU64>,
    protected_requests: Arc<AtomicU64>,
}

impl AuthJourneyProbe {
    fn proof(&self) -> serde_json::Value {
        serde_json::json!({
            "meRequests": self.me_requests.load(Ordering::SeqCst),
            "capabilityRequests": self.capability_requests.load(Ordering::SeqCst),
            "oidcStartRequests": self.oidc_start_requests.load(Ordering::SeqCst),
            "enterpriseStartRequests": self.enterprise_start_requests.load(Ordering::SeqCst),
            "enterpriseContinueRequests": self.enterprise_continue_requests.load(Ordering::SeqCst),
            "protectedRequests": self.protected_requests.load(Ordering::SeqCst),
        })
    }
}

#[derive(Clone)]
struct FixtureChannels {
    rows: Arc<Mutex<Vec<ChannelSummary>>>,
    next: Arc<AtomicU64>,
}

impl FixtureChannels {
    fn new(now: OffsetDateTime) -> Self {
        let rows = (0..52)
            .map(|index| ChannelSummary {
                id: ChannelId::new(format!("channel-{index:02}")),
                name: if index == 0 {
                    "Finance Operations".to_owned()
                } else {
                    format!("Channel {index:02}")
                },
                agent_ids: vec![BotId::new(format!("bot-{}", index % 4))],
                last_message: Some(if index == 0 {
                    "Categorized three expenses.".to_owned()
                } else {
                    format!("Fixture activity {index:02}")
                }),
                last_message_at: Some(now - Duration::minutes(i64::from(index))),
                last_message_agent_id: Some(BotId::new(format!("bot-{}", index % 4))),
                created_at: now - Duration::days(2) - Duration::minutes(i64::from(index)),
                thread_id: match index {
                    0 => Some(ThreadId::new(FIXTURE_EXISTING_THREAD)),
                    1 => Some(ThreadId::new(FIXTURE_APPROVAL_THREAD)),
                    2 => Some(ThreadId::new(FIXTURE_CHOICE_THREAD)),
                    _ => None,
                },
                active: index != 3,
            })
            .collect();
        Self {
            rows: Arc::new(Mutex::new(rows)),
            next: Arc::new(AtomicU64::new(1)),
        }
    }

    fn read(&self, limit: u32, cursor: Option<ChannelCursor>) -> Vec<ChannelSummary> {
        let mut rows = self.rows.lock().expect("fixture channel lock").clone();
        if let Some(cursor) = cursor {
            rows.retain(|row| {
                let recency = row.last_message_at.unwrap_or(row.created_at);
                (recency, &row.id) < (cursor.recency, &cursor.id)
            });
        }
        rows.truncate(limit as usize);
        rows
    }
}

#[async_trait]
impl ChannelReader for FixtureChannels {
    async fn list_visible_channels(
        &self,
        _actor: &ActorId,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        Ok(self.read(limit, cursor))
    }

    async fn list_visible_channels_scoped(
        &self,
        _scope: &ChannelReadScope,
        limit: u32,
        cursor: Option<ChannelCursor>,
    ) -> Result<Vec<ChannelSummary>, PortError> {
        Ok(self.read(limit, cursor))
    }

    async fn get_visible_channel(
        &self,
        _scope: &ChannelReadScope,
        channel_id: &ChannelId,
    ) -> Result<Option<ChannelSummary>, PortError> {
        Ok(self
            .rows
            .lock()
            .expect("fixture channel lock")
            .iter()
            .find(|row| &row.id == channel_id)
            .cloned())
    }
}

#[async_trait]
impl ChannelAdministration for FixtureChannels {
    async fn create_channel(
        &self,
        request: ChannelCreateRequest,
    ) -> Result<ChannelDetail, ChannelAdministrationError> {
        let sequence = self.next.fetch_add(1, Ordering::SeqCst);
        let id = ChannelId::new(format!("channel-created-{sequence}"));
        let thread_id = ThreadId::new(uuid::Uuid::now_v7().to_string());
        let name = request
            .agent_ids
            .iter()
            .map(|id| id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let created_at = OffsetDateTime::now_utc();
        self.rows
            .lock()
            .map_err(|_| ChannelAdministrationError::Unavailable)?
            .insert(
                0,
                ChannelSummary {
                    id: id.clone(),
                    name: name.clone(),
                    agent_ids: request.agent_ids.clone(),
                    last_message: None,
                    last_message_at: None,
                    last_message_agent_id: None,
                    created_at,
                    thread_id: Some(thread_id.clone()),
                    active: true,
                },
            );
        Ok(ChannelDetail {
            id,
            name,
            agent_ids: request.agent_ids,
            thread_id: Some(thread_id),
            active: true,
        })
    }
}

#[derive(Clone)]
struct FixtureAgents {
    rows: Arc<Mutex<Vec<AgentProfile>>>,
    next: Arc<AtomicU64>,
    callback_sequence: Arc<AtomicU64>,
}

impl FixtureAgents {
    fn new() -> Self {
        Self {
            rows: Arc::new(Mutex::new(vec![
                AgentProfile {
                    id: BotId::new("fixture-owned-private"),
                    name: "Research Partner".to_owned(),
                    title: "Private research coworker".to_owned(),
                    role_description: "Finds primary sources and keeps citations attached to every conclusion.".to_owned(),
                    avatar_seed: "fixture-research".to_owned(),
                    visibility: AgentVisibility::Private,
                    endpoint: Some("https://research.example.test/ag-ui".to_owned()),
                    has_auth: true,
                    has_callback_token: true,
                    hidden: false,
                    system_owned: false,
                    can_manage: true,
                    mine: true,
                },
                AgentProfile {
                    id: BotId::new("fixture-owned-public"),
                    name: "Operations Guide".to_owned(),
                    title: "Operations coworker".to_owned(),
                    role_description: "Turns recurring operating work into clear, reviewable checklists.".to_owned(),
                    avatar_seed: "fixture-operations".to_owned(),
                    visibility: AgentVisibility::Public,
                    endpoint: None,
                    has_auth: false,
                    has_callback_token: false,
                    hidden: false,
                    system_owned: false,
                    can_manage: true,
                    mine: true,
                },
                AgentProfile {
                    id: BotId::new("fixture-system-public"),
                    name: "Knowledge Desk".to_owned(),
                    title: "System knowledge coworker".to_owned(),
                    role_description: "Answers from the deployment knowledge package without exposing its internals.".to_owned(),
                    avatar_seed: "fixture-knowledge".to_owned(),
                    visibility: AgentVisibility::Public,
                    endpoint: None,
                    has_auth: false,
                    has_callback_token: false,
                    hidden: false,
                    system_owned: true,
                    can_manage: false,
                    mine: false,
                },
                AgentProfile {
                    id: BotId::new("fixture-explore-public"),
                    name: "Risk Analyst".to_owned(),
                    title: "Shared risk coworker".to_owned(),
                    role_description: "Reviews operational changes and identifies controls that need evidence.".to_owned(),
                    avatar_seed: "fixture-risk".to_owned(),
                    visibility: AgentVisibility::Public,
                    endpoint: Some("https://risk.example.test/ag-ui".to_owned()),
                    has_auth: false,
                    has_callback_token: false,
                    hidden: false,
                    system_owned: false,
                    can_manage: false,
                    mine: false,
                },
                AgentProfile {
                    id: BotId::new("fixture-hidden-private"),
                    name: "Hidden Counsel".to_owned(),
                    title: "Hidden private coworker".to_owned(),
                    role_description: "A directly addressable coworker hidden from the default roster.".to_owned(),
                    avatar_seed: "fixture-hidden".to_owned(),
                    visibility: AgentVisibility::Private,
                    endpoint: None,
                    has_auth: false,
                    has_callback_token: false,
                    hidden: true,
                    system_owned: false,
                    can_manage: true,
                    mine: true,
                },
            ])),
            next: Arc::new(AtomicU64::new(1)),
            callback_sequence: Arc::new(AtomicU64::new(1)),
        }
    }
}

#[async_trait]
impl AgentDirectory for FixtureAgents {
    async fn list_visible_agents(
        &self,
        _scope: &AgentReadScope,
        hidden: bool,
    ) -> Result<Vec<AgentProfile>, PortError> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::Unavailable {
                dependency: "fixture_agents",
            })?
            .iter()
            .filter(|profile| profile.hidden == hidden)
            .cloned()
            .collect())
    }

    async fn get_visible_agent(
        &self,
        _scope: &AgentReadScope,
        agent_id: &BotId,
    ) -> Result<Option<AgentProfile>, PortError> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| PortError::Unavailable {
                dependency: "fixture_agents",
            })?
            .iter()
            .find(|profile| &profile.id == agent_id)
            .cloned())
    }
}

#[async_trait]
impl AgentAdministration for FixtureAgents {
    async fn create_agent(
        &self,
        _scope: &AgentAdministrationScope,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let sequence = self.next.fetch_add(1, Ordering::SeqCst);
        let profile = AgentProfile {
            id: BotId::new(format!("fixture-user-agent-{sequence}")),
            name: request.name,
            title: request.title,
            role_description: request.role_description,
            avatar_seed: format!("fixture-user-agent-{sequence}"),
            visibility: request.visibility,
            endpoint: request.endpoint,
            has_auth: request.auth.is_some(),
            has_callback_token: false,
            hidden: false,
            system_owned: false,
            can_manage: true,
            mine: true,
        };
        self.rows
            .lock()
            .map_err(|_| AgentAdministrationError::Unavailable)?
            .push(profile.clone());
        Ok(profile)
    }

    async fn update_agent(
        &self,
        _scope: &AgentAdministrationScope,
        agent_id: &BotId,
        request: AgentMutationRequest,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentAdministrationError::Unavailable)?;
        let profile = rows
            .iter_mut()
            .find(|profile| &profile.id == agent_id)
            .ok_or(AgentAdministrationError::NotVisible)?;
        if profile.system_owned {
            return Err(AgentAdministrationError::Protected);
        }
        if !profile.can_manage {
            return Err(AgentAdministrationError::Forbidden);
        }
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
        _scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentProfile, AgentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentAdministrationError::Unavailable)?;
        let source = rows
            .iter()
            .find(|profile| &profile.id == agent_id)
            .cloned()
            .ok_or(AgentAdministrationError::NotVisible)?;
        let sequence = self.next.fetch_add(1, Ordering::SeqCst);
        let copy = AgentProfile {
            id: BotId::new(format!("fixture-user-agent-{sequence}")),
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
        _scope: &AgentAdministrationScope,
        agent_id: &BotId,
        hidden: bool,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentAdministrationError::Unavailable)?;
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
        _scope: &AgentAdministrationScope,
        agent_id: &BotId,
    ) -> Result<AgentLifecycleReceipt, AgentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentAdministrationError::Unavailable)?;
        let index = rows
            .iter()
            .position(|profile| &profile.id == agent_id)
            .ok_or(AgentAdministrationError::NotVisible)?;
        if rows[index].system_owned {
            return Err(AgentAdministrationError::Protected);
        }
        if !rows[index].can_manage {
            return Err(AgentAdministrationError::Forbidden);
        }
        rows.remove(index);
        Ok(AgentLifecycleReceipt {
            agent_id: agent_id.clone(),
            state: AgentLifecycleState::Deleted,
        })
    }

    async fn test_agent_connection(
        &self,
        _scope: &AgentAdministrationScope,
        _request: AgentConnectionTestRequest,
    ) -> Result<AgentConnectionVerdict, AgentAdministrationError> {
        Ok(AgentConnectionVerdict::working(vec![
            "RUN_STARTED".to_owned(),
        ]))
    }
}

#[async_trait]
impl AgentCallbackTokenAdministration for FixtureAgents {
    async fn issue(
        &self,
        auth: &AuthContext,
        agent_id: &BotId,
    ) -> Result<CallbackTokenIssued, AgentCallbackTokenError> {
        if !fixture_callback_authorized(auth) {
            return Err(AgentCallbackTokenError::NotVisible);
        }
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentCallbackTokenError::Unavailable)?;
        let profile = rows
            .iter_mut()
            .find(|profile| {
                &profile.id == agent_id
                    && profile.endpoint.is_some()
                    && profile.can_manage
                    && !profile.system_owned
            })
            .ok_or(AgentCallbackTokenError::NotVisible)?;
        let sequence = self.callback_sequence.fetch_add(1, Ordering::SeqCst);
        let token = CallbackTokenIssued::new(format!("obot_agt_fixture_callback_{sequence:032}"))
            .map_err(|_| AgentCallbackTokenError::Corrupt { field: "token" })?;
        profile.has_callback_token = true;
        Ok(token)
    }

    async fn revoke(
        &self,
        auth: &AuthContext,
        agent_id: &BotId,
    ) -> Result<CallbackTokenRevoked, AgentCallbackTokenError> {
        if !fixture_callback_authorized(auth) {
            return Err(AgentCallbackTokenError::NotVisible);
        }
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| AgentCallbackTokenError::Unavailable)?;
        let profile = rows
            .iter_mut()
            .find(|profile| {
                &profile.id == agent_id
                    && profile.endpoint.is_some()
                    && profile.can_manage
                    && !profile.system_owned
            })
            .ok_or(AgentCallbackTokenError::NotVisible)?;
        profile.has_callback_token = false;
        Ok(CallbackTokenRevoked)
    }
}

fn fixture_callback_authorized(auth: &AuthContext) -> bool {
    auth.deployment().as_str() == FIXTURE_DEPLOYMENT
        && auth.tenant().as_str() == FIXTURE_TENANT
        && auth.actor().as_str() == FIXTURE_ACTOR
        && auth.auth_generation() == AuthGeneration::new(1)
        && auth.has_role(Role::User)
}

#[derive(Clone)]
struct FixtureRouting {
    inner: Arc<FixtureRoutingInner>,
}

struct FixtureRoutingInner {
    complete_calls: AtomicU64,
    reach_calls: AtomicU64,
    record_attempts: AtomicU64,
    recorded: AtomicU64,
    explicit: AtomicU64,
    inferred: AtomicU64,
    fallback: AtomicU64,
    failed_records: AtomicU64,
    fail_next_record: AtomicBool,
    last_chosen: Mutex<Option<String>>,
}

#[derive(Clone)]
struct FixtureRoutingProbe {
    inner: Arc<FixtureRoutingInner>,
}

impl FixtureRouting {
    fn new() -> Self {
        Self {
            inner: Arc::new(FixtureRoutingInner {
                complete_calls: AtomicU64::new(0),
                reach_calls: AtomicU64::new(0),
                record_attempts: AtomicU64::new(0),
                recorded: AtomicU64::new(0),
                explicit: AtomicU64::new(0),
                inferred: AtomicU64::new(0),
                fallback: AtomicU64::new(0),
                failed_records: AtomicU64::new(0),
                fail_next_record: AtomicBool::new(false),
                last_chosen: Mutex::new(None),
            }),
        }
    }

    fn probe(&self) -> FixtureRoutingProbe {
        FixtureRoutingProbe {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl ChannelRoutingBackend for FixtureRouting {
    async fn complete(&self, prompt: &str) -> Result<String, ChannelRoutingBackendError> {
        self.inner.complete_calls.fetch_add(1, Ordering::SeqCst);
        if prompt.contains(FIXTURE_ROUTING_FALLBACK_CANARY) {
            self.inner.fail_next_record.store(true, Ordering::SeqCst);
            return Err(ChannelRoutingBackendError::Unavailable);
        }
        Ok(serde_json::json!({
            "agentId":"fixture-explore-public",
            "reason":"fixture specialist match",
            "confidence":0.9,
        })
        .to_string())
    }

    async fn reachable_systems(
        &self,
        agents: &[BotId],
    ) -> Result<Vec<AgentReachability>, ChannelRoutingBackendError> {
        self.inner.reach_calls.fetch_add(1, Ordering::SeqCst);
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
        record: RoutingAuditRecord,
    ) -> Result<(), ChannelRoutingBackendError> {
        self.inner.record_attempts.fetch_add(1, Ordering::SeqCst);
        if self.inner.fail_next_record.swap(false, Ordering::SeqCst) {
            self.inner.failed_records.fetch_add(1, Ordering::SeqCst);
            return Err(ChannelRoutingBackendError::Unavailable);
        }
        self.inner.recorded.fetch_add(1, Ordering::SeqCst);
        if record.via_mention {
            self.inner.explicit.fetch_add(1, Ordering::SeqCst);
        } else {
            self.inner.inferred.fetch_add(1, Ordering::SeqCst);
        }
        if record.fallback {
            self.inner.fallback.fetch_add(1, Ordering::SeqCst);
        }
        *self
            .inner
            .last_chosen
            .lock()
            .map_err(|_| ChannelRoutingBackendError::Unavailable)? =
            Some(record.chosen.as_str().to_owned());
        Ok(())
    }
}

async fn fixture_routing_probe(probe: FixtureRoutingProbe) -> axum::Json<serde_json::Value> {
    let last_chosen = probe
        .inner
        .last_chosen
        .lock()
        .ok()
        .and_then(|chosen| chosen.clone());
    axum::Json(serde_json::json!({
        "completeCalls": probe.inner.complete_calls.load(Ordering::SeqCst),
        "reachCalls": probe.inner.reach_calls.load(Ordering::SeqCst),
        "recordAttempts": probe.inner.record_attempts.load(Ordering::SeqCst),
        "recorded": probe.inner.recorded.load(Ordering::SeqCst),
        "explicit": probe.inner.explicit.load(Ordering::SeqCst),
        "inferred": probe.inner.inferred.load(Ordering::SeqCst),
        "fallback": probe.inner.fallback.load(Ordering::SeqCst),
        "failedRecords": probe.inner.failed_records.load(Ordering::SeqCst),
        "lastChosen": last_chosen,
    }))
}

async fn fixture_fail_next_routing_record(
    probe: FixtureRoutingProbe,
) -> axum::Json<serde_json::Value> {
    probe.inner.fail_next_record.store(true, Ordering::SeqCst);
    axum::Json(serde_json::json!({"armed":true}))
}

async fn fixture_home_probe(
    channels: FixtureChannels,
    routing: FixtureRoutingProbe,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let (channel_count, created) = {
        let rows = channels
            .rows
            .lock()
            .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
        let created = rows
            .iter()
            .filter(|channel| channel.id.as_str().starts_with("channel-created-"))
            .map(|channel| {
                serde_json::json!({
                    "id":channel.id,
                    "agentIds":channel.agent_ids,
                    "threadId":channel.thread_id,
                })
            })
            .collect::<Vec<_>>();
        (rows.len(), created)
    };
    let routing = fixture_routing_probe(routing).await.0;
    Ok(axum::Json(serde_json::json!({
        "channelCount": channel_count,
        "created": created,
        "routing": routing,
    })))
}

#[derive(Clone)]
struct FixtureConnections {
    actor: ActorId,
    redirect_uri: String,
    connected_at: OffsetDateTime,
    connection: Arc<Mutex<Option<McpConnection>>>,
}

impl FixtureConnections {
    fn new(actor: ActorId, port: u16, connected_at: OffsetDateTime) -> Self {
        Self {
            actor,
            redirect_uri: format!("http://127.0.0.1:{port}/api/plugins/oauth/callback"),
            connected_at,
            connection: Arc::new(Mutex::new(None)),
        }
    }

    fn ensure_actor(&self, auth: &AuthContext) -> Result<(), McpConnectionError> {
        if auth.actor() == &self.actor {
            Ok(())
        } else {
            Err(McpConnectionError::NotVisible)
        }
    }

    fn ensure_server(server_id: &str) -> Result<(), McpConnectionError> {
        if server_id == FIXTURE_GOOGLE_DRIVE_SERVER {
            Ok(())
        } else {
            Err(McpConnectionError::NotVisible)
        }
    }
}

#[async_trait]
impl McpConnectionAdministration for FixtureConnections {
    async fn list_connections(
        &self,
        auth: &AuthContext,
    ) -> Result<McpConnections, McpConnectionError> {
        self.ensure_actor(auth)?;
        Ok(McpConnections {
            available_server_ids: vec![FIXTURE_GOOGLE_DRIVE_SERVER.to_owned()],
            connections: self
                .connection
                .lock()
                .map_err(|_| McpConnectionError::Unavailable)?
                .iter()
                .cloned()
                .collect(),
            redirect_uri: Some(self.redirect_uri.clone()),
        })
    }

    async fn begin_oauth(
        &self,
        auth: &AuthContext,
        server_id: &str,
        return_to: McpOAuthReturnTo,
    ) -> Result<McpOAuthAuthorization, McpConnectionError> {
        self.ensure_actor(auth)?;
        Self::ensure_server(server_id)?;
        if return_to != McpOAuthReturnTo::Settings {
            return Err(McpConnectionError::InvalidInput { field: "return_to" });
        }
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        *self
            .connection
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)? = Some(McpConnection {
            server_id: server_id.to_owned(),
            scope: FIXTURE_GOOGLE_DRIVE_SCOPE.to_owned(),
            connected_at: self.connected_at,
        });
        Ok(McpOAuthAuthorization {
            authorization_url: "/settings/connected-accounts?connected=google-drive".to_owned(),
        })
    }

    async fn disconnect(
        &self,
        auth: &AuthContext,
        server_id: &str,
    ) -> Result<McpConnectionDisconnected, McpConnectionError> {
        self.ensure_actor(auth)?;
        Self::ensure_server(server_id)?;
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        let removed = self
            .connection
            .lock()
            .map_err(|_| McpConnectionError::Unavailable)?
            .take();
        if removed.is_none() {
            return Err(McpConnectionError::NotVisible);
        }
        Ok(McpConnectionDisconnected {
            server_id: server_id.to_owned(),
            vendor_revocation: McpVendorRevocationStatus::Pending,
        })
    }

    async fn register_oauth_client(
        &self,
        _auth: &AuthContext,
        _server_id: &str,
        _registration: &McpOAuthClientRegistration,
    ) -> Result<McpOAuthClientRegistered, McpConnectionError> {
        Err(McpConnectionError::Unavailable)
    }
}

#[derive(Clone)]
struct FixtureComponents {
    rows: Arc<Mutex<Vec<ComponentRecord>>>,
    decisions: Arc<Mutex<Vec<FixtureHumanDecision>>>,
    threads: FixtureThreads,
    now: OffsetDateTime,
}

#[derive(Clone)]
struct FixtureHumanDecision {
    thread_id: ThreadId,
    pending: PendingComponentHumanDecision,
    answer: Option<ComponentHumanDecisionAnswer>,
}

impl FixtureComponents {
    fn new(now: OffsetDateTime, threads: FixtureThreads) -> Self {
        Self {
            rows: Arc::new(Mutex::new(vec![
                ComponentRecord {
                    name: "showLegacyWidget".to_owned(),
                    title: "Legacy widget".to_owned(),
                    kind: CompiledComponentKind::Card,
                    draft_description: "A published row whose renderer left this build.".to_owned(),
                    published_description: Some(
                        "A published row whose renderer left this build.".to_owned(),
                    ),
                    published: true,
                    published_at: Some(now - Duration::days(2)),
                    updated_by: Some("fixture-admin".to_owned()),
                    updated_at: now - Duration::days(2),
                    has_unpublished_changes: false,
                    withheld_from: Vec::new(),
                    functions: Vec::new(),
                },
                ComponentRecord {
                    name: "showFutureChart".to_owned(),
                    title: "Future chart".to_owned(),
                    kind: CompiledComponentKind::Chart,
                    draft_description: "An unpublished fixture row.".to_owned(),
                    published_description: None,
                    published: false,
                    published_at: None,
                    updated_by: Some("fixture-admin".to_owned()),
                    updated_at: now - Duration::days(1),
                    has_unpublished_changes: true,
                    withheld_from: vec!["fixture-owned-private".to_owned()],
                    functions: vec!["readFixture".to_owned()],
                },
                ComponentRecord {
                    name: "custom_delivery_eta".to_owned(),
                    title: "Delivery ETA".to_owned(),
                    kind: CompiledComponentKind::Sandboxed,
                    draft_description: "Show a delivery estimate.".to_owned(),
                    published_description: Some("Show a delivery estimate.".to_owned()),
                    published: true,
                    published_at: Some(now),
                    updated_by: Some("fixture-actor".to_owned()),
                    updated_at: now,
                    has_unpublished_changes: false,
                    withheld_from: Vec::new(),
                    functions: Vec::new(),
                },
            ])),
            decisions: Arc::new(Mutex::new(vec![
                FixtureHumanDecision {
                    thread_id: ThreadId::new(FIXTURE_APPROVAL_THREAD),
                    pending: PendingComponentHumanDecision {
                        decision_id: "fixture-decision-approval".to_owned(),
                        run_id: RunId::new(FIXTURE_APPROVAL_RUN),
                        provider_call_id: "fixture-provider-approval".to_owned(),
                        agent_id: BotId::new("bot-1"),
                        component_name: ASK_APPROVAL_COMPONENT_NAME.to_owned(),
                        arguments: serde_json::json!({
                            "title":"Refund this order?",
                            "summary":"The customer was charged twice for the same order.",
                            "details":[
                                {"label":"Amount","value":"$128.40"},
                                {"label":"Order","value":"2043"}
                            ],
                            "approveLabel":"Refund"
                        }),
                        requested_at: now - Duration::minutes(1),
                        expires_at: now + Duration::minutes(30),
                    },
                    answer: None,
                },
                FixtureHumanDecision {
                    thread_id: ThreadId::new(FIXTURE_CHOICE_THREAD),
                    pending: PendingComponentHumanDecision {
                        decision_id: "fixture-decision-choice".to_owned(),
                        run_id: RunId::new(FIXTURE_CHOICE_RUN),
                        provider_call_id: "fixture-provider-choice".to_owned(),
                        agent_id: BotId::new("bot-2"),
                        component_name: ASK_CHOICE_COMPONENT_NAME.to_owned(),
                        arguments: serde_json::json!({
                            "title":"Where should this go?",
                            "summary":"Choose the destination environment.",
                            "options":[
                                {"id":"staging","label":"Staging"},
                                {"id":"production","label":"Production","description":"Live customers"}
                            ]
                        }),
                        requested_at: now,
                        expires_at: now + Duration::minutes(30),
                    },
                    answer: None,
                },
            ])),
            threads,
            now,
        }
    }
}

#[async_trait]
impl ComponentAdministration for FixtureComponents {
    async fn list_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<ComponentRecords, ComponentAdministrationError> {
        let mut components = self
            .rows
            .lock()
            .map_err(|_| ComponentAdministrationError::Unavailable)?
            .clone();
        components.sort_by(|left, right| {
            (left.kind.as_str(), &left.title, &left.name).cmp(&(
                right.kind.as_str(),
                &right.title,
                &right.name,
            ))
        });
        Ok(ComponentRecords { components })
    }

    async fn sync_catalogue(
        &self,
        _auth: &AuthContext,
        entries: &[CompiledComponentManifestEntry],
    ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ComponentAdministrationError::Unavailable)?;
        let mut added = Vec::new();
        for entry in entries {
            if rows.iter().any(|row| row.name == entry.name) {
                continue;
            }
            rows.push(ComponentRecord {
                name: entry.name.clone(),
                title: entry.title.clone(),
                kind: entry.kind,
                draft_description: entry.description.clone(),
                published_description: Some(entry.description.clone()),
                published: true,
                published_at: Some(self.now),
                updated_by: Some("the build".to_owned()),
                updated_at: self.now,
                has_unpublished_changes: false,
                withheld_from: Vec::new(),
                functions: Vec::new(),
            });
            added.push(entry.name.clone());
        }
        Ok(ComponentCatalogueAdded { added })
    }

    async fn update_component_governance(
        &self,
        auth: &AuthContext,
        mutation: &ComponentGovernanceMutation,
    ) -> Result<ComponentRecord, ComponentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| ComponentAdministrationError::Unavailable)?;
        let row = rows
            .iter_mut()
            .find(|row| row.name == mutation.component_name())
            .ok_or(ComponentAdministrationError::NotVisible)?;
        match mutation {
            ComponentGovernanceMutation::SetAgentGrant {
                agent_id, granted, ..
            } => {
                if *granted {
                    row.withheld_from.retain(|value| value != agent_id.as_str());
                } else if !row
                    .withheld_from
                    .iter()
                    .any(|value| value == agent_id.as_str())
                {
                    row.withheld_from.push(agent_id.as_str().to_owned());
                    row.withheld_from.sort();
                }
            }
            ComponentGovernanceMutation::SetFunctionGrant {
                function, granted, ..
            } => {
                if row.kind == CompiledComponentKind::Sandboxed {
                    return Err(ComponentAdministrationError::Conflict);
                }
                if *granted {
                    if !row.functions.contains(function) {
                        row.functions.push(function.clone());
                        row.functions.sort();
                    }
                } else {
                    row.functions.retain(|value| value != function);
                }
            }
            ComponentGovernanceMutation::SetPublication { published, .. } => {
                if row.kind == CompiledComponentKind::Sandboxed {
                    return Err(ComponentAdministrationError::Conflict);
                }
                row.published = *published;
                if *published {
                    row.published_description = Some(row.draft_description.clone());
                    row.published_at = Some(self.now);
                }
                row.updated_by = Some(auth.actor().as_str().to_owned());
                row.updated_at = self.now;
            }
            ComponentGovernanceMutation::SaveDraft { description, .. } => {
                if row.kind == CompiledComponentKind::Sandboxed {
                    return Err(ComponentAdministrationError::Conflict);
                }
                row.draft_description = description.clone();
                row.updated_by = Some(auth.actor().as_str().to_owned());
                row.updated_at = self.now;
            }
        }
        row.has_unpublished_changes =
            row.draft_description != row.published_description.as_deref().unwrap_or("");
        Ok(row.clone())
    }

    async fn call_component_function(
        &self,
        scope: &ComponentRuntimeScope,
        component_name: &str,
        build_has_renderer: bool,
        plan: &ComponentFunctionCallPlan,
    ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
        if scope.agent_id.as_str() != "bot-0"
            || component_name != SHOW_ACTIVITY_REPORT_COMPONENT_NAME
            || !build_has_renderer
        {
            return Err(ComponentAdministrationError::NotVisible);
        }
        match plan.arguments {
            Some(ComponentFunctionArguments::BotActivity { days })
                if plan.function == BOT_ACTIVITY_FUNCTION_NAME =>
            {
                Ok(ComponentFunctionCall::succeeded(
                    ComponentFunctionData::BotActivity(BotActivityReport {
                        days,
                        rows: vec![
                            BotActivityRow {
                                bot: "bot-busiest".to_owned(),
                                actions: 9,
                            },
                            BotActivityRow {
                                bot: "bot-secondary".to_owned(),
                                actions: 4,
                            },
                        ],
                    }),
                ))
            }
            Some(ComponentFunctionArguments::RecentRefusals { .. })
                if plan.function == RECENT_REFUSALS_FUNCTION_NAME =>
            {
                Ok(ComponentFunctionCall::succeeded(
                    ComponentFunctionData::RecentRefusals(RecentRefusalsReport {
                        rows: vec![RecentRefusalRow {
                            at: self.now,
                            bot: Some("bot-0".to_owned()),
                            what: "component.refused".to_owned(),
                            reason: Some("component_withheld".to_owned()),
                        }],
                    }),
                ))
            }
            _ => Err(ComponentAdministrationError::InvalidInput {
                field: "fixture_component_function",
            }),
        }
    }

    async fn list_component_human_decisions(
        &self,
        _auth: &AuthContext,
    ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
        let mut decisions = self
            .decisions
            .lock()
            .map_err(|_| ComponentAdministrationError::Unavailable)?
            .iter()
            .filter(|decision| decision.answer.is_none())
            .map(|decision| decision.pending.clone())
            .collect::<Vec<_>>();
        decisions.sort_by(|left, right| {
            (left.requested_at, &left.decision_id).cmp(&(right.requested_at, &right.decision_id))
        });
        Ok(PendingComponentHumanDecisions { decisions })
    }

    async fn resolve_component_human_decision(
        &self,
        _auth: &AuthContext,
        decision_id: &str,
        answer: &ComponentHumanDecisionAnswer,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        let (thread_id, pending, replayed) = {
            let mut decisions = self
                .decisions
                .lock()
                .map_err(|_| ComponentAdministrationError::Unavailable)?;
            let decision = decisions
                .iter_mut()
                .find(|decision| decision.pending.decision_id == decision_id)
                .ok_or(ComponentAdministrationError::NotVisible)?;
            validate_component_human_decision_answer(
                &decision.pending.component_name,
                &decision.pending.arguments,
                answer,
            )
            .map_err(|_| ComponentAdministrationError::InvalidInput {
                field: "component_answer",
            })?;
            let replayed = match &decision.answer {
                Some(stored) if stored == answer => true,
                Some(_) => return Err(ComponentAdministrationError::Conflict),
                None => {
                    decision.answer = Some(answer.clone());
                    false
                }
            };
            (
                decision.thread_id.clone(),
                decision.pending.clone(),
                replayed,
            )
        };
        if !replayed {
            self.threads
                .complete_human_decision(&thread_id, &pending, answer)?;
        }
        Ok(ComponentHumanDecisionResolved {
            decision_id: decision_id.to_owned(),
            answer: answer.clone(),
            replayed,
        })
    }
}

#[derive(Clone)]
struct FixtureSandboxed {
    retired: Arc<Mutex<std::collections::BTreeSet<String>>>,
    rows: Arc<Mutex<Vec<SandboxedComponentRecord>>>,
    now: OffsetDateTime,
}

fn fixture_sandbox_stale(
    row: &SandboxedComponentRecord,
) -> Result<SandboxedComponentAdministrationError, SandboxedComponentAdministrationError> {
    openbot_contracts::revision::RevisionSnapshot::from_public(
        row.editing_revision,
        row.updated_at,
        row,
    )
    .map(SandboxedComponentAdministrationError::StaleSnapshot)
    .map_err(|_| SandboxedComponentAdministrationError::Unavailable)
}

impl FixtureSandboxed {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            retired: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            rows: Arc::new(Mutex::new(vec![SandboxedComponentRecord {
                editing_revision: 1,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
                name: "custom_delivery_eta".to_owned(),
                title: "Delivery ETA".to_owned(),
                draft_description: "Show a delivery estimate.".to_owned(),
                draft_html: "<div class=\"eta\"><strong id=\"eta-title\"></strong><span id=\"eta-body\"></span></div>".to_owned(),
                draft_css: ".eta { display: grid; gap: 6px; padding: 12px; font: 14px system-ui; }".to_owned(),
                draft_js_functions: "document.getElementById('eta-title').textContent = window.__args.title || 'Delivery'; document.getElementById('eta-body').textContent = window.__args.body || ''; document.body.dataset.argsInjected = window.__args.title || '';".to_owned(),
                draft_argument_schema: BTreeMap::from([
                    ("type".to_owned(), serde_json::json!("object")),
                    ("properties".to_owned(), serde_json::json!({"title":{"type":"string"},"body":{"type":"string"}})),
                ]),
                published_html: Some("<div class=\"eta\"><strong id=\"eta-title\"></strong><span id=\"eta-body\"></span></div>".to_owned()),
                published_css: Some(".eta { display: grid; gap: 6px; padding: 12px; font: 14px system-ui; }".to_owned()),
                published_js_functions: Some("document.getElementById('eta-title').textContent = window.__args.title || 'Delivery'; document.getElementById('eta-body').textContent = window.__args.body || ''; document.body.dataset.argsInjected = window.__args.title || '';".to_owned()),
                published_argument_schema: Some(BTreeMap::from([
                    ("type".to_owned(), serde_json::json!("object")),
                    ("properties".to_owned(), serde_json::json!({"title":{"type":"string"},"body":{"type":"string"}})),
                ])),
                sample_arguments: BTreeMap::from([
                    ("title".to_owned(), serde_json::json!("Arrives tomorrow")),
                    ("body".to_owned(), serde_json::json!("Tracked from the published fixture.")),
                ]),
                revision: 1,
                published: true,
                published_at: Some(now),
                authored_by: Some("fixture-actor".to_owned()),
                has_unpublished_changes: false,
            }])),
            now,
        }
    }
}

#[async_trait]
impl SandboxedComponentAdministration for FixtureSandboxed {
    async fn list_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<SandboxedComponents, SandboxedComponentAdministrationError> {
        let mut components = self
            .rows
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?
            .clone();
        components
            .sort_by(|left, right| (&left.title, &left.name).cmp(&(&right.title, &right.name)));
        Ok(SandboxedComponents { components })
    }

    async fn list_published_sandboxed_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<PublishedSandboxedComponents, SandboxedComponentAdministrationError> {
        let rows = self
            .rows
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?;
        let mut components = rows
            .iter()
            .filter(|row| row.published)
            .map(|row| PublishedSandboxedComponent {
                name: row.name.clone(),
                html: row.published_html.clone().unwrap_or_default(),
                css: row.published_css.clone().unwrap_or_default(),
                js_functions: row.published_js_functions.clone().unwrap_or_default(),
                argument_schema: row.published_argument_schema.clone().unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        components.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(PublishedSandboxedComponents { components })
    }

    async fn save_sandboxed_component(
        &self,
        auth: &AuthContext,
        draft: &SandboxedComponentDraft,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?;
        if self
            .retired
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?
            .contains(&draft.name)
        {
            return Err(SandboxedComponentAdministrationError::Conflict);
        }
        if let Some(row) = rows.iter_mut().find(|row| row.name == draft.name) {
            if draft.expected_revision != Some(row.editing_revision) {
                return Err(fixture_sandbox_stale(row)?);
            }
            let next = row
                .editing_revision
                .checked_add(1)
                .ok_or(SandboxedComponentAdministrationError::Conflict)?;
            row.editing_revision = next;
            row.updated_at = self.now;
            row.title = draft.title.clone();
            row.draft_description = draft.description.clone();
            row.draft_html = draft.html.clone();
            row.draft_css = draft.css.clone();
            row.draft_js_functions = draft.js_functions.clone();
            row.draft_argument_schema = draft.argument_schema.clone();
            row.sample_arguments = draft.sample_arguments.clone();
            row.authored_by = Some(auth.actor().as_str().to_owned());
            row.has_unpublished_changes = row.published
                && (row.published_html.as_deref() != Some(row.draft_html.as_str())
                    || row.published_css.as_deref() != Some(row.draft_css.as_str())
                    || row.published_js_functions.as_deref()
                        != Some(row.draft_js_functions.as_str()));
            return Ok(row.clone());
        }
        if draft.expected_revision.is_some() {
            return Err(SandboxedComponentAdministrationError::NotVisible);
        }
        let row = SandboxedComponentRecord {
            editing_revision: 1,
            updated_at: self.now,
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
        };
        rows.push(row.clone());
        Ok(row)
    }

    async fn publish_sandboxed_component(
        &self,
        _auth: &AuthContext,
        component_name: &str,
        expected_revision: i64,
    ) -> Result<SandboxedComponentRecord, SandboxedComponentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?;
        let row = rows
            .iter_mut()
            .find(|row| row.name == component_name)
            .ok_or(SandboxedComponentAdministrationError::NotVisible)?;
        if row.editing_revision != expected_revision {
            return Err(fixture_sandbox_stale(row)?);
        }
        let next = row
            .editing_revision
            .checked_add(1)
            .ok_or(SandboxedComponentAdministrationError::Conflict)?;
        let publication = row
            .revision
            .checked_add(1)
            .ok_or(SandboxedComponentAdministrationError::Conflict)?;
        row.editing_revision = next;
        row.updated_at = self.now;
        row.published_html = Some(row.draft_html.clone());
        row.published_css = Some(row.draft_css.clone());
        row.published_js_functions = Some(row.draft_js_functions.clone());
        row.published_argument_schema = Some(row.draft_argument_schema.clone());
        row.revision = publication;
        row.published = true;
        row.published_at = Some(self.now);
        row.has_unpublished_changes = false;
        Ok(row.clone())
    }

    async fn delete_sandboxed_component(
        &self,
        _auth: &AuthContext,
        component_name: &str,
        expected_revision: i64,
    ) -> Result<(), SandboxedComponentAdministrationError> {
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?;
        let row = rows
            .iter()
            .find(|r| r.name == component_name)
            .ok_or(SandboxedComponentAdministrationError::NotVisible)?;
        if row.editing_revision != expected_revision {
            return Err(fixture_sandbox_stale(row)?);
        }
        self.retired
            .lock()
            .map_err(|_| SandboxedComponentAdministrationError::Unavailable)?
            .insert(component_name.to_owned());
        let before = rows.len();
        rows.retain(|row| row.name != component_name);
        if rows.len() == before {
            return Err(SandboxedComponentAdministrationError::NotVisible);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct FixtureMemory {
    tenant: TenantId,
    actor: ActorId,
    writes_enabled: Arc<AtomicBool>,
    rows: Arc<Mutex<Vec<MemoryRecord>>>,
    next: Arc<AtomicU64>,
}

impl FixtureMemory {
    fn new(tenant: TenantId, actor: ActorId, now: OffsetDateTime) -> Self {
        let rows = (0..52)
            .map(|index| {
                let status = match index {
                    3 => MemoryStatus::Superseded,
                    4 => MemoryStatus::Forbidden,
                    5 => MemoryStatus::Deleted,
                    _ => MemoryStatus::Active,
                };
                let memory_kind = if index == 1 {
                    MemoryKind::Fact
                } else {
                    MemoryKind::Preference
                };
                let scope = match index {
                    1 => MemoryScope::Thread {
                        thread_id: ThreadId::new(FIXTURE_EXISTING_THREAD),
                    },
                    2 => MemoryScope::Bot {
                        bot_id: BotId::new("fixture-owned-private"),
                    },
                    _ => MemoryScope::User,
                };
                let content = match index {
                    0 => Some("Prefers concise answers with primary-source citations.".to_owned()),
                    1 => Some("The finance review is scheduled for Friday.".to_owned()),
                    2 => Some("Use the private research coworker for source audits.".to_owned()),
                    3 => Some("Superseded fixture preference.".to_owned()),
                    4 | 5 => None,
                    _ => Some(format!("Fixture memory entry {index:02}")),
                };
                MemoryRecord {
                    memory_id: format!("memory-{index:02}"),
                    owner_user_id: actor.as_str().to_owned(),
                    scope,
                    memory_kind,
                    content,
                    tags: match index {
                        0 => vec!["writing".to_owned(), "citations".to_owned()],
                        1 => vec!["finance".to_owned()],
                        2 => vec!["research".to_owned()],
                        _ => vec!["fixture".to_owned()],
                    },
                    sensitivity: if index == 2 {
                        MemorySensitivity::Sensitive
                    } else {
                        MemorySensitivity::Normal
                    },
                    source: (index == 1).then(|| MemorySource {
                        thread_id: ThreadId::new(FIXTURE_EXISTING_THREAD),
                        message_id: "fixture-user-message".to_owned(),
                    }),
                    source_run_id: None,
                    source_authorization_snapshot: None,
                    origin: match index {
                        1 | 2 => MemoryOrigin::RememberTool,
                        6 => MemoryOrigin::VerifiedImport,
                        _ => MemoryOrigin::UserAction,
                    },
                    created_by: actor.as_str().to_owned(),
                    supersedes_id: None,
                    status,
                    expires_at: None,
                    created_at: now - Duration::minutes(i64::from(index)),
                    updated_at: now - Duration::minutes(i64::from(index)),
                }
            })
            .collect();
        Self {
            tenant,
            actor,
            writes_enabled: Arc::new(AtomicBool::new(true)),
            rows: Arc::new(Mutex::new(rows)),
            next: Arc::new(AtomicU64::new(1)),
        }
    }

    fn ensure_scope(
        &self,
        tenant: &TenantId,
        actor: &ActorId,
    ) -> Result<(), MemoryAdministrationError> {
        if tenant == &self.tenant && actor == &self.actor {
            Ok(())
        } else {
            Err(MemoryAdministrationError::NotVisible)
        }
    }

    fn ensure_writes_enabled(&self) -> Result<(), MemoryAdministrationError> {
        if self.writes_enabled.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(MemoryAdministrationError::WritesDisabled)
        }
    }

    fn next_id(&self) -> String {
        let sequence = self.next.fetch_add(1, Ordering::SeqCst);
        format!("memory-fixture-{sequence}")
    }
}

#[async_trait]
impl MemoryAdministration for FixtureMemory {
    async fn memory_control(
        &self,
        request: MemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        Ok(MemoryControl {
            writes_enabled: self.writes_enabled.load(Ordering::SeqCst),
        })
    }

    async fn update_memory_control(
        &self,
        request: UpdateMemoryControlRequest,
    ) -> Result<MemoryControl, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        self.writes_enabled
            .store(request.update.writes_enabled, Ordering::SeqCst);
        Ok(MemoryControl {
            writes_enabled: request.update.writes_enabled,
        })
    }

    async fn remember(
        &self,
        request: RememberMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        self.ensure_writes_enabled()?;
        let now = OffsetDateTime::now_utc();
        let mut tags = request.input.tags;
        tags.sort();
        tags.dedup();
        let record = MemoryRecord {
            memory_id: self.next_id(),
            owner_user_id: request.actor.as_str().to_owned(),
            scope: request.input.scope,
            memory_kind: request.input.memory_kind,
            content: Some(request.input.content),
            tags,
            sensitivity: request.input.sensitivity,
            source: request.input.source,
            source_run_id: None,
            source_authorization_snapshot: None,
            origin: MemoryOrigin::UserAction,
            created_by: request.actor.as_str().to_owned(),
            supersedes_id: None,
            status: MemoryStatus::Active,
            expires_at: request.input.expires_at,
            created_at: now,
            updated_at: now,
        };
        self.rows
            .lock()
            .map_err(|_| MemoryAdministrationError::Unavailable)?
            .insert(0, record.clone());
        Ok(record)
    }

    async fn list_memories(
        &self,
        request: MemoryPageRequest,
    ) -> Result<MemoryPage, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        let rows = self
            .rows
            .lock()
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let start = if let Some(cursor) = request.cursor.as_deref() {
            rows.iter()
                .position(|record| record.memory_id == cursor)
                .map(|position| position.saturating_add(1))
                .ok_or(MemoryAdministrationError::InvalidInput { field: "cursor" })?
        } else {
            0
        };
        let limit = request.limit as usize;
        let memories = rows
            .iter()
            .skip(start)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = (rows.len() > start.saturating_add(memories.len()))
            .then(|| memories.last().map(|record| record.memory_id.clone()))
            .flatten();
        Ok(MemoryPage {
            memories,
            next_cursor,
        })
    }

    async fn correct(
        &self,
        request: CorrectMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        self.ensure_writes_enabled()?;
        let now = OffsetDateTime::now_utc();
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let old = rows
            .iter_mut()
            .find(|record| record.memory_id == request.memory_id)
            .ok_or(MemoryAdministrationError::NotVisible)?;
        if old.status != MemoryStatus::Active {
            return Err(MemoryAdministrationError::Conflict);
        }
        old.status = MemoryStatus::Superseded;
        old.updated_at = now;
        let old = old.clone();
        let mut tags = request.correction.tags;
        tags.sort();
        tags.dedup();
        let replacement = MemoryRecord {
            memory_id: self.next_id(),
            owner_user_id: request.actor.as_str().to_owned(),
            scope: old.scope,
            memory_kind: old.memory_kind,
            content: Some(request.correction.content),
            tags,
            sensitivity: request.correction.sensitivity,
            source: old.source,
            source_run_id: None,
            source_authorization_snapshot: None,
            origin: MemoryOrigin::UserAction,
            created_by: request.actor.as_str().to_owned(),
            supersedes_id: Some(old.memory_id),
            status: MemoryStatus::Active,
            expires_at: request.correction.expires_at,
            created_at: now,
            updated_at: now,
        };
        rows.insert(0, replacement.clone());
        Ok(replacement)
    }

    async fn mutate(
        &self,
        request: MutateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        let mut rows = self
            .rows
            .lock()
            .map_err(|_| MemoryAdministrationError::Unavailable)?;
        let record = rows
            .iter_mut()
            .find(|record| record.memory_id == request.memory_id)
            .ok_or(MemoryAdministrationError::NotVisible)?;
        record.status = match request.mutation {
            MemoryMutation::Forbid if record.status == MemoryStatus::Deleted => {
                MemoryStatus::Deleted
            }
            MemoryMutation::Forbid => MemoryStatus::Forbidden,
            MemoryMutation::Delete => MemoryStatus::Deleted,
        };
        record.content = None;
        record.updated_at = OffsetDateTime::now_utc();
        Ok(record.clone())
    }

    async fn recall(
        &self,
        request: RecallMemoriesRequest,
    ) -> Result<MemoryRecall, MemoryAdministrationError> {
        self.ensure_scope(&request.tenant, &request.actor)?;
        let query = request.input.query.to_lowercase();
        let now = OffsetDateTime::now_utc();
        let limit = request.input.limit.unwrap_or(50).clamp(1, 100) as usize;
        let memories = self
            .rows
            .lock()
            .map_err(|_| MemoryAdministrationError::Unavailable)?
            .iter()
            .filter(|record| record.status == MemoryStatus::Active)
            .filter(|record| record.expires_at.is_none_or(|expiry| expiry > now))
            .filter(|record| {
                record
                    .content
                    .as_deref()
                    .is_some_and(|content| content.to_lowercase().contains(&query))
            })
            .filter(|record| {
                request
                    .input
                    .tags
                    .iter()
                    .all(|tag| record.tags.contains(tag))
            })
            .filter(|record| match &record.scope {
                MemoryScope::User => true,
                MemoryScope::Bot { bot_id } => request.input.bot_id.as_ref() == Some(bot_id),
                MemoryScope::Thread { thread_id } => {
                    request.input.thread_id.as_ref() == Some(thread_id)
                }
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(MemoryRecall { memories })
    }
}

#[derive(Clone)]
struct FixtureAudit {
    events: Arc<Vec<AuditEventView>>,
}

impl FixtureAudit {
    fn new(now: OffsetDateTime) -> Self {
        let events = (0..52)
            .map(|index| AuditEventView {
                id: AuditEventId::new(format!("fixture-audit-{index:02}")),
                actor_user_id: (index % 5 != 0).then(|| ActorId::new(FIXTURE_ACTOR)),
                event_type: if index % 3 == 0 {
                    "tool.approval_granted".to_owned()
                } else {
                    "agent.invoked".to_owned()
                },
                target_type: if index % 3 == 0 {
                    "tool_approval".to_owned()
                } else {
                    "run".to_owned()
                },
                target_id: Some(format!("fixture-target-{index:02}")),
                payload: serde_json::json!({
                    "sequence": index,
                    "outcome": if index % 3 == 0 { "granted" } else { "started" }
                }),
                created_at: now - Duration::seconds(i64::from(index)),
            })
            .collect();
        Self {
            events: Arc::new(events),
        }
    }
}

#[async_trait]
impl AuditReader for FixtureAudit {
    async fn list_audit_events(
        &self,
        request: AuditPageRequest,
    ) -> Result<AuditPage, AuditReadError> {
        if !request.event_types.is_empty()
            || request.actor_user_id.is_some()
            || request.target_type.is_some()
            || request.target_id.is_some()
            || request.from.is_some()
            || request.to.is_some()
            || request.limit != 50
        {
            return Err(AuditReadError::Corrupt {
                field: "fixture_audit_request",
            });
        }
        let start = match request.cursor.as_deref() {
            None => 0,
            Some("fixture-audit-page-2") => 50,
            Some(_) => return Err(AuditReadError::InvalidCursor),
        };
        let end = (start + request.limit as usize).min(self.events.len());
        Ok(AuditPage {
            events: self.events[start..end].to_vec(),
            next_cursor: (end < self.events.len()).then(|| "fixture-audit-page-2".to_owned()),
        })
    }
}

#[derive(Clone)]
struct FixturePeople {
    rows: Arc<Mutex<Vec<Person>>>,
}

impl FixturePeople {
    fn new(now: OffsetDateTime) -> Self {
        let rows = (0..52)
            .map(|index| {
                let (id, email, name, role, revoked, configured_admin) = match index {
                    0 => (
                        FIXTURE_ACTOR.to_owned(),
                        "fixture@example.test".to_owned(),
                        "Fixture Administrator".to_owned(),
                        Role::Admin,
                        false,
                        false,
                    ),
                    1 => (
                        "fixture-configured-admin".to_owned(),
                        FIXTURE_CONFIGURED_ADMIN_EMAIL.to_owned(),
                        "Configured Administrator".to_owned(),
                        Role::Admin,
                        false,
                        true,
                    ),
                    2 => (
                        "fixture-revoked".to_owned(),
                        "revoked@example.test".to_owned(),
                        "Revoked Person".to_owned(),
                        Role::User,
                        true,
                        false,
                    ),
                    51 => (
                        "fixture-search-target".to_owned(),
                        "outside-first-page@example.test".to_owned(),
                        "Search Target".to_owned(),
                        Role::User,
                        false,
                        false,
                    ),
                    _ => (
                        format!("fixture-person-{index:02}"),
                        format!("person-{index:02}@example.test"),
                        format!("Fixture Person {index:02}"),
                        Role::User,
                        false,
                        false,
                    ),
                };
                let providers = match index % 4 {
                    0 => vec!["google".to_owned()],
                    1 => vec!["microsoft".to_owned()],
                    2 => vec!["okta".to_owned()],
                    _ => Vec::new(),
                };
                Person {
                    id: ActorId::new(id),
                    email,
                    name: Some(name),
                    image: None,
                    role,
                    providers,
                    last_signed_in_at: (index != 3)
                        .then_some(now - Duration::days(i64::from(index))),
                    revoked,
                    configured_admin,
                }
            })
            .collect();
        Self {
            rows: Arc::new(Mutex::new(rows)),
        }
    }

    fn cursor_offset(cursor: Option<&str>) -> usize {
        cursor
            .and_then(|cursor| cursor.strip_prefix("fixture-people-offset-"))
            .and_then(|offset| offset.parse().ok())
            .unwrap_or(0)
    }
}

#[derive(Clone)]
enum FixturePeoplePort {
    Memory(FixturePeople),
    Postgres(PostgresPeopleAdministration),
}

#[async_trait]
impl PeopleAdministration for FixturePeoplePort {
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        match self {
            Self::Memory(people) => people.current_user(actor).await,
            Self::Postgres(people) => people.current_user(actor).await,
        }
    }

    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError> {
        match self {
            Self::Memory(people) => people.list_people(request).await,
            Self::Postgres(people) => people.list_people(request).await,
        }
    }

    async fn change_role(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        desired: Role,
    ) -> Result<Person, PeoplePortError> {
        match self {
            Self::Memory(people) => people.change_role(actor, subject, desired).await,
            Self::Postgres(people) => people.change_role(actor, subject, desired).await,
        }
    }

    async fn change_access(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        revoked: bool,
    ) -> Result<Person, PeoplePortError> {
        match self {
            Self::Memory(people) => people.change_access(actor, subject, revoked).await,
            Self::Postgres(people) => people.change_access(actor, subject, revoked).await,
        }
    }
}

#[async_trait]
impl PeopleAdministration for FixturePeople {
    async fn current_user(&self, actor: &ActorId) -> Result<CurrentUser, PeoplePortError> {
        let rows = self.rows.lock().map_err(|_| PeoplePortError::Unavailable)?;
        let person = rows
            .iter()
            .find(|person| &person.id == actor)
            .ok_or(PeoplePortError::NotFound)?;
        Ok(CurrentUser {
            id: person.id.clone(),
            email: person.email.clone(),
            name: person.name.clone(),
            image: person.image.clone(),
            role: person.role,
        })
    }

    async fn list_people(&self, request: PeoplePageRequest) -> Result<PeoplePage, PeoplePortError> {
        let query = request.search.as_deref().map(str::to_lowercase);
        let rows = self.rows.lock().map_err(|_| PeoplePortError::Unavailable)?;
        let filtered = rows
            .iter()
            .filter(|person| {
                query.as_ref().is_none_or(|query| {
                    person.email.to_lowercase().contains(query)
                        || person
                            .name
                            .as_deref()
                            .is_some_and(|name| name.to_lowercase().contains(query))
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let start = Self::cursor_offset(request.cursor.as_deref()).min(filtered.len());
        let end = (start + request.limit as usize).min(filtered.len());
        Ok(PeoplePage {
            people: filtered[start..end].to_vec(),
            next_cursor: (end < filtered.len()).then(|| format!("fixture-people-offset-{end}")),
        })
    }

    async fn change_role(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        desired: Role,
    ) -> Result<Person, PeoplePortError> {
        let mut rows = self.rows.lock().map_err(|_| PeoplePortError::Unavailable)?;
        let person = rows
            .iter_mut()
            .find(|person| &person.id == subject)
            .ok_or(PeoplePortError::NotFound)?;
        if person.configured_admin && desired != Role::Admin {
            return Err(PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::RoleConfiguredAdmin,
            });
        }
        if actor == subject && desired != Role::Admin {
            return Err(PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::RoleSelfDemotion,
            });
        }
        person.role = desired;
        Ok(person.clone())
    }

    async fn change_access(
        &self,
        actor: &ActorId,
        subject: &ActorId,
        revoked: bool,
    ) -> Result<Person, PeoplePortError> {
        let mut rows = self.rows.lock().map_err(|_| PeoplePortError::Unavailable)?;
        let person = rows
            .iter_mut()
            .find(|person| &person.id == subject)
            .ok_or(PeoplePortError::NotFound)?;
        if person.configured_admin && revoked {
            return Err(PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::AccessConfiguredAdmin,
            });
        }
        if actor == subject && revoked {
            return Err(PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::AccessSelfRevocation,
            });
        }
        person.revoked = revoked;
        Ok(person.clone())
    }
}

#[derive(Clone)]
struct FixtureThreads {
    inner: Arc<FixtureThreadsInner>,
    channels: FixtureChannels,
}

struct FixtureThreadsInner {
    snapshots: Mutex<HashMap<String, ThreadConversationSnapshot>>,
    events: Mutex<HashMap<String, Vec<ThreadRunEvent>>>,
    subscribers: Mutex<HashMap<String, Vec<tokio::sync::mpsc::Sender<AppEvent>>>>,
    receipts: Mutex<HashMap<String, ThreadRunStarted>>,
    cancelled_runs: Mutex<HashSet<String>>,
    direct_runs: Mutex<Vec<FixtureDirectRunFact>>,
    mint_calls: AtomicU64,
    status_checks: AtomicU64,
    conversation_reads: AtomicU64,
    fail_activity_follow_up_once: AtomicBool,
}

#[derive(Clone)]
struct FixtureDirectRunFact {
    thread_id: String,
    run_id: String,
    bot_id: String,
}

impl FixtureThreads {
    fn new(channels: FixtureChannels) -> Self {
        let mut snapshots = HashMap::new();
        snapshots.insert(
            FIXTURE_EXISTING_THREAD.to_owned(),
            ThreadConversationSnapshot {
                messages: vec![
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-user-message".to_owned(),
                        role: ThreadHistoryRole::User,
                        content: "Categorize these expenses.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-assistant-message".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: "Categorized three expenses.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-component-call".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: String::new(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: Some(vec![serde_json::json!({
                            "id":"fixture-provider-component",
                            "type":"function",
                            "function":{
                                "name":"showQuote",
                                "arguments":{
                                    "quote":"Receipts are required above $75.",
                                    "attribution":"the expense policy",
                                    "context":"Fixture durable component"
                                }
                            }
                        })]),
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-component-result".to_owned(),
                        role: ThreadHistoryRole::Tool,
                        content: "The quotation is now on screen for the person.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: Some("fixture-provider-component".to_owned()),
                        tool_name: Some("showQuote".to_owned()),
                        tool_error_code: None,
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-activity-component-call".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: String::new(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: Some(vec![serde_json::json!({
                            "id":"fixture-provider-activity-component",
                            "type":"function",
                            "function":{
                                "name":"showActivityReport",
                                "arguments":{"report":"activity","days":7}
                            }
                        })]),
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-activity-component-result".to_owned(),
                        role: ThreadHistoryRole::Tool,
                        content: "The report is on screen for the person, filled with figures read from this deployment. You were not given the figures.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: Some("fixture-provider-activity-component".to_owned()),
                        tool_name: Some("showActivityReport".to_owned()),
                        tool_error_code: None,
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-refusals-component-call".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: String::new(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: Some(vec![serde_json::json!({
                            "id":"fixture-provider-refusals-component",
                            "type":"function",
                            "function":{
                                "name":"showActivityReport",
                                "arguments":{"report":"refusals"}
                            }
                        })]),
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-refusals-component-result".to_owned(),
                        role: ThreadHistoryRole::Tool,
                        content: "The report is on screen for the person, filled with figures read from this deployment. You were not given the figures.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: Some("fixture-provider-refusals-component".to_owned()),
                        tool_name: Some("showActivityReport".to_owned()),
                        tool_error_code: None,
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-refused-component-call".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: String::new(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: Some(vec![serde_json::json!({
                            "id":"fixture-provider-refused-component",
                            "type":"function",
                            "function":{
                                "name":"showNotice",
                                "arguments":{"title":"Would have shown","body":"Refused fixture"}
                            }
                        })]),
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-refused-component-result".to_owned(),
                        role: ThreadHistoryRole::Tool,
                        content: "Not shown: Notice.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: Some("fixture-provider-refused-component".to_owned()),
                        tool_name: Some("showNotice".to_owned()),
                        tool_error_code: Some("component_withheld".to_owned()),
                        tool_calls: None,
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-sandboxed-component-call".to_owned(),
                        role: ThreadHistoryRole::Assistant,
                        content: String::new(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: Some(vec![serde_json::json!({
                            "id":"fixture-provider-sandboxed-component",
                            "type":"function",
                            "function":{
                                "name":"custom_delivery_eta",
                                "arguments":{
                                    "title":"Arrives tomorrow",
                                    "body":"Rendered from published sandbox source."
                                }
                            }
                        })]),
                    },
                    ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: "fixture-sandboxed-component-result".to_owned(),
                        role: ThreadHistoryRole::Tool,
                        content: "It is now on screen for the person.".to_owned(),
                        agent_id: Some(BotId::new("bot-0")),
                        tool_call_id: Some("fixture-provider-sandboxed-component".to_owned()),
                        tool_name: Some("custom_delivery_eta".to_owned()),
                        tool_error_code: None,
                        tool_calls: None,
                    },
                ],
                active_run_id: None,
                active_run_state: None,
                active_run_cancellable: false,
                active_run_text: String::new(),
                last_event_sequence: None,
            },
        );
        for (thread, run, bot, prompt) in [
            (
                FIXTURE_APPROVAL_THREAD,
                FIXTURE_APPROVAL_RUN,
                "bot-1",
                "Please ask me before refunding the duplicate charge.",
            ),
            (
                FIXTURE_CHOICE_THREAD,
                FIXTURE_CHOICE_RUN,
                "bot-2",
                "Ask which environment I want.",
            ),
        ] {
            snapshots.insert(
                thread.to_owned(),
                ThreadConversationSnapshot {
                    messages: vec![ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: format!("{run}:user"),
                        role: ThreadHistoryRole::User,
                        content: prompt.to_owned(),
                        agent_id: Some(BotId::new(bot)),
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: None,
                    }],
                    active_run_id: Some(RunId::new(run)),
                    active_run_state: Some(ThreadForegroundRunState::Running),
                    active_run_cancellable: true,
                    active_run_text: String::new(),
                    last_event_sequence: Some(0),
                },
            );
        }
        Self {
            inner: Arc::new(FixtureThreadsInner {
                snapshots: Mutex::new(snapshots),
                events: Mutex::new(HashMap::new()),
                subscribers: Mutex::new(HashMap::new()),
                receipts: Mutex::new(HashMap::new()),
                cancelled_runs: Mutex::new(HashSet::new()),
                direct_runs: Mutex::new(Vec::new()),
                mint_calls: AtomicU64::new(0),
                status_checks: AtomicU64::new(0),
                conversation_reads: AtomicU64::new(0),
                fail_activity_follow_up_once: AtomicBool::new(true),
            }),
            channels,
        }
    }

    fn proof(&self) -> Result<serde_json::Value, ()> {
        let runs = self.inner.direct_runs.lock().map_err(|_| ())?;
        let snapshots = self.inner.snapshots.lock().map_err(|_| ())?;
        let direct_threads = runs
            .iter()
            .map(|run| run.thread_id.as_str())
            .collect::<BTreeSet<_>>();
        let last = runs.last();
        let last_snapshot = last.and_then(|run| snapshots.get(&run.thread_id));
        Ok(serde_json::json!({
            "mintCalls": self.inner.mint_calls.load(Ordering::SeqCst),
            "statusChecks": self.inner.status_checks.load(Ordering::SeqCst),
            "conversationReads": self.inner.conversation_reads.load(Ordering::SeqCst),
            "directRuns": runs.len(),
            "directThreads": direct_threads.len(),
            "persistedDirectThreads": direct_threads
                .iter()
                .filter(|thread| snapshots.contains_key(**thread))
                .count(),
            "lastThreadId": last.map(|run| run.thread_id.clone()),
            "lastRunId": last.map(|run| run.run_id.clone()),
            "lastBotId": last.map(|run| run.bot_id.clone()),
            "lastMessages": last_snapshot.map(|snapshot| snapshot.messages.len()),
            "lastActive": last_snapshot.and_then(|snapshot| snapshot.active_run_id.as_ref()).is_some(),
        }))
    }

    fn publish(&self, thread: &ThreadId, event: ThreadRunEvent) {
        self.inner
            .events
            .lock()
            .expect("fixture events lock")
            .entry(thread.as_str().to_owned())
            .or_default()
            .push(event.clone());
        if let Some(subscribers) = self
            .inner
            .subscribers
            .lock()
            .expect("fixture subscribers lock")
            .get_mut(thread.as_str())
        {
            subscribers.retain(|sender| {
                sender
                    .try_send(AppEvent::ThreadRunEvent(event.clone()))
                    .is_ok()
            });
        }
    }

    fn complete_human_decision(
        &self,
        thread: &ThreadId,
        pending: &PendingComponentHumanDecision,
        answer: &ComponentHumanDecisionAnswer,
    ) -> Result<(), ComponentAdministrationError> {
        let result = serde_json::to_string(answer)
            .map_err(|_| ComponentAdministrationError::Corrupt { field: "answer" })?;
        let event_sequence = {
            let mut snapshots = self
                .inner
                .snapshots
                .lock()
                .map_err(|_| ComponentAdministrationError::Unavailable)?;
            let snapshot = snapshots
                .get_mut(thread.as_str())
                .ok_or(ComponentAdministrationError::NotVisible)?;
            if snapshot.active_run_id.as_ref() != Some(&pending.run_id) {
                return Err(ComponentAdministrationError::NotVisible);
            }
            snapshot.messages.push(ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: format!("{}:assistant", pending.decision_id),
                role: ThreadHistoryRole::Assistant,
                content: String::new(),
                agent_id: Some(pending.agent_id.clone()),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: Some(vec![serde_json::json!({
                    "id":pending.provider_call_id,
                    "type":"function",
                    "function":{
                        "name":pending.component_name,
                        "arguments":pending.arguments,
                    }
                })]),
            });
            snapshot.messages.push(ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: format!("{}:tool", pending.decision_id),
                role: ThreadHistoryRole::Tool,
                content: result,
                agent_id: Some(pending.agent_id.clone()),
                tool_call_id: Some(pending.provider_call_id.clone()),
                tool_name: Some(pending.component_name.clone()),
                tool_error_code: None,
                tool_calls: None,
            });
            snapshot.active_run_id = None;
            snapshot.active_run_state = None;
            snapshot.active_run_cancellable = false;
            snapshot.active_run_text.clear();
            let sequence = snapshot
                .last_event_sequence
                .map_or(0, |value| value.saturating_add(1));
            snapshot.last_event_sequence = Some(sequence);
            sequence
        };
        self.publish(
            thread,
            ThreadRunEvent {
                thread_id: thread.clone(),
                run_id: pending.run_id.clone(),
                event_sequence,
                event_type: ThreadRunEventKind::Completed,
                payload: serde_json::json!({"status":"completed"}),
                terminal: true,
                created_at: pending.requested_at,
            },
        );
        Ok(())
    }
}

#[async_trait]
impl ThreadDirectory for FixtureThreads {
    async fn mint_thread_id(
        &self,
        _deployment: &DeploymentId,
    ) -> Result<ThreadId, ThreadDirectoryError> {
        self.inner.mint_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ThreadId::new(uuid::Uuid::now_v7().to_string()))
    }

    async fn thread_known(
        &self,
        _deployment: &DeploymentId,
        _tenant: &TenantId,
        _actor: &ActorId,
        thread: &ThreadId,
    ) -> Result<bool, ThreadDirectoryError> {
        self.inner.status_checks.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .inner
            .snapshots
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .contains_key(thread.as_str()))
    }

    async fn begin_thread_run(
        &self,
        request: BeginThreadRunRequest,
    ) -> Result<ThreadRunStarted, ThreadDirectoryError> {
        if let Some(receipt) = self
            .inner
            .receipts
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .get(request.command.run_id.as_str())
            .cloned()
        {
            return Ok(ThreadRunStarted {
                replayed: true,
                ..receipt
            });
        }
        if request.command.message == FIXTURE_ACTIVITY_FOLLOW_UP
            && self
                .inner
                .fail_activity_follow_up_once
                .swap(false, Ordering::SeqCst)
        {
            return Err(ThreadDirectoryError::Unavailable);
        }
        let thread = request.command.thread_id.clone();
        let run = request.command.run_id.clone();
        let bot = request.command.bot_id.clone();
        if let openbot_contracts::command::ThreadRunAnchor::Channel { channel_id } =
            &request.command.anchor
            && let Ok(mut channels) = self.channels.rows.lock()
            && let Some(channel) = channels
                .iter_mut()
                .find(|channel| channel.id == *channel_id)
        {
            channel.thread_id = Some(thread.clone());
        }
        let (message_sequence, event_sequence) = {
            let mut snapshots = self
                .inner
                .snapshots
                .lock()
                .map_err(|_| ThreadDirectoryError::Unavailable)?;
            let snapshot = snapshots.entry(thread.as_str().to_owned()).or_default();
            let message_sequence = u64::try_from(snapshot.messages.len()).map_err(|_| {
                ThreadDirectoryError::Corrupt {
                    field: "fixture_sequence",
                }
            })?;
            let event_sequence = snapshot
                .last_event_sequence
                .map_or(0, |value| value.saturating_add(1));
            snapshot.messages.push(ThreadHistoryMessage {
                selected_skill_slugs: Vec::new(),
                id: format!("{}:user", run.as_str()),
                role: ThreadHistoryRole::User,
                content: request.command.message.clone(),
                agent_id: Some(bot.clone()),
                tool_call_id: None,
                tool_name: None,
                tool_error_code: None,
                tool_calls: None,
            });
            snapshot.active_run_id = Some(run.clone());
            snapshot.active_run_state = Some(ThreadForegroundRunState::Running);
            snapshot.active_run_cancellable = true;
            snapshot.active_run_text.clear();
            snapshot.last_event_sequence = Some(event_sequence);
            (message_sequence, event_sequence)
        };
        let started = ThreadRunStarted {
            thread_id: thread.clone(),
            run_id: run.clone(),
            message_sequence,
            event_sequence,
            replayed: false,
        };
        self.inner
            .receipts
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .insert(run.as_str().to_owned(), started.clone());
        if matches!(&request.command.anchor, ThreadRunAnchor::DirectBot) {
            self.inner
                .direct_runs
                .lock()
                .map_err(|_| ThreadDirectoryError::Unavailable)?
                .push(FixtureDirectRunFact {
                    thread_id: thread.as_str().to_owned(),
                    run_id: run.as_str().to_owned(),
                    bot_id: bot.as_str().to_owned(),
                });
        }
        self.publish(
            &thread,
            ThreadRunEvent {
                thread_id: thread.clone(),
                run_id: run.clone(),
                event_sequence,
                event_type: ThreadRunEventKind::Started,
                payload: serde_json::json!({"runId":run,"messageId":format!("{}:user",run.as_str()),"botId":bot.clone()}),
                terminal: false,
                created_at: OffsetDateTime::now_utc(),
            },
        );
        let runtime = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            if runtime
                .inner
                .cancelled_runs
                .lock()
                .is_ok_and(|runs| runs.contains(run.as_str()))
            {
                return;
            }
            let chunk_sequence = event_sequence.saturating_add(1);
            if let Ok(mut snapshots) = runtime.inner.snapshots.lock()
                && let Some(snapshot) = snapshots.get_mut(thread.as_str())
            {
                snapshot.active_run_text = "Fixture reply".to_owned();
                snapshot.last_event_sequence = Some(chunk_sequence);
            }
            runtime.publish(
                &thread,
                ThreadRunEvent {
                    thread_id: thread.clone(),
                    run_id: run.clone(),
                    event_sequence: chunk_sequence,
                    event_type: ThreadRunEventKind::SemanticChunk,
                    payload: serde_json::json!({"channel":"text","delta":"Fixture reply"}),
                    terminal: false,
                    created_at: OffsetDateTime::now_utc(),
                },
            );
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            if runtime
                .inner
                .cancelled_runs
                .lock()
                .is_ok_and(|runs| runs.contains(run.as_str()))
            {
                return;
            }
            let terminal_sequence = chunk_sequence.saturating_add(1);
            if let Ok(mut snapshots) = runtime.inner.snapshots.lock()
                && let Some(snapshot) = snapshots.get_mut(thread.as_str())
            {
                snapshot.messages.push(ThreadHistoryMessage {
                    selected_skill_slugs: Vec::new(),
                    id: format!("{}:assistant", run.as_str()),
                    role: ThreadHistoryRole::Assistant,
                    content: "Fixture reply".to_owned(),
                    agent_id: Some(bot.clone()),
                    tool_call_id: None,
                    tool_name: None,
                    tool_error_code: None,
                    tool_calls: None,
                });
                snapshot.active_run_id = None;
                snapshot.active_run_state = None;
                snapshot.active_run_cancellable = false;
                snapshot.active_run_text.clear();
                snapshot.last_event_sequence = Some(terminal_sequence);
            }
            runtime.publish(
                &thread,
                ThreadRunEvent {
                    thread_id: thread.clone(),
                    run_id: run,
                    event_sequence: terminal_sequence,
                    event_type: ThreadRunEventKind::Completed,
                    payload: serde_json::json!({"status":"completed"}),
                    terminal: true,
                    created_at: OffsetDateTime::now_utc(),
                },
            );
        });
        Ok(started)
    }

    async fn cancel_thread_run(
        &self,
        request: CancelThreadRunRequest,
    ) -> Result<ThreadRunCancellation, ThreadDirectoryError> {
        let run_id = request.command.run_id.clone();
        let thread_id = request.command.thread_id.clone();
        {
            let mut snapshots = self
                .inner
                .snapshots
                .lock()
                .map_err(|_| ThreadDirectoryError::Unavailable)?;
            let Some(snapshot) = snapshots.get_mut(thread_id.as_str()) else {
                return Err(ThreadDirectoryError::NotVisible);
            };
            if snapshot.active_run_id.as_ref() != Some(&run_id) {
                return Ok(ThreadRunCancellation {
                    thread_id,
                    run_id,
                    state: ThreadRunCancellationState::AlreadyTerminal,
                });
            }
            if matches!(
                snapshot.active_run_state,
                Some(ThreadForegroundRunState::Cancelling)
            ) {
                return Ok(ThreadRunCancellation {
                    thread_id,
                    run_id,
                    state: ThreadRunCancellationState::AlreadyRequested,
                });
            }
            snapshot.active_run_state = Some(ThreadForegroundRunState::Cancelling);
            snapshot.active_run_cancellable = false;
        }
        self.inner
            .cancelled_runs
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .insert(run_id.as_str().to_owned());
        let runtime = self.clone();
        let terminal_thread = thread_id.clone();
        let terminal_run = run_id.clone();
        tokio::spawn(async move {
            // Production only emits Cancelled after the cancellation token has stopped the child.
            // Keep that observable ordering in the browser fixture instead of collapsing both
            // states into one fake repository call.
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            let terminal_sequence = {
                let Ok(mut snapshots) = runtime.inner.snapshots.lock() else {
                    return;
                };
                let Some(snapshot) = snapshots.get_mut(terminal_thread.as_str()) else {
                    return;
                };
                if snapshot.active_run_id.as_ref() != Some(&terminal_run)
                    || !matches!(
                        snapshot.active_run_state,
                        Some(ThreadForegroundRunState::Cancelling)
                    )
                {
                    return;
                }
                let terminal_sequence = snapshot
                    .last_event_sequence
                    .map_or(0, |value| value.saturating_add(1));
                if !snapshot.active_run_text.is_empty() {
                    snapshot.messages.push(ThreadHistoryMessage {
                        selected_skill_slugs: Vec::new(),
                        id: format!("{}:assistant", terminal_run.as_str()),
                        role: ThreadHistoryRole::Assistant,
                        content: snapshot.active_run_text.clone(),
                        agent_id: None,
                        tool_call_id: None,
                        tool_name: None,
                        tool_error_code: None,
                        tool_calls: None,
                    });
                }
                snapshot.active_run_id = None;
                snapshot.active_run_state = None;
                snapshot.active_run_text.clear();
                snapshot.last_event_sequence = Some(terminal_sequence);
                terminal_sequence
            };
            runtime.publish(
                &terminal_thread,
                ThreadRunEvent {
                    thread_id: terminal_thread.clone(),
                    run_id: terminal_run.clone(),
                    event_sequence: terminal_sequence,
                    event_type: ThreadRunEventKind::Cancelled,
                    payload: serde_json::json!({"status":"cancelled"}),
                    terminal: true,
                    created_at: OffsetDateTime::now_utc(),
                },
            );
        });
        Ok(ThreadRunCancellation {
            thread_id,
            run_id,
            state: ThreadRunCancellationState::Requested,
        })
    }

    async fn thread_history(
        &self,
        request: ThreadHistoryRequest,
    ) -> Result<ThreadHistory, ThreadDirectoryError> {
        Ok(ThreadHistory {
            messages: self
                .inner
                .snapshots
                .lock()
                .map_err(|_| ThreadDirectoryError::Unavailable)?
                .get(request.thread.as_str())
                .map(|snapshot| snapshot.messages.clone())
                .unwrap_or_default(),
        })
    }

    async fn thread_conversation(
        &self,
        request: ThreadConversationRequest,
    ) -> Result<ThreadConversationSnapshot, ThreadDirectoryError> {
        self.inner.conversation_reads.fetch_add(1, Ordering::SeqCst);
        self.inner
            .snapshots
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .get(request.thread.as_str())
            .cloned()
            .ok_or(ThreadDirectoryError::NotVisible)
    }

    async fn subscribe_thread_events(
        &self,
        request: ThreadEventSubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let cursor = request.after_event_sequence;
        for event in self
            .inner
            .events
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .get(request.thread.as_str())
            .into_iter()
            .flatten()
            .filter(|event| cursor.is_none_or(|cursor| event.event_sequence > cursor))
        {
            sender
                .try_send(AppEvent::ThreadRunEvent(event.clone()))
                .map_err(|_| ThreadDirectoryError::Unavailable)?;
        }
        self.inner
            .subscribers
            .lock()
            .map_err(|_| ThreadDirectoryError::Unavailable)?
            .entry(request.thread.as_str().to_owned())
            .or_default()
            .push(sender);
        Ok(Box::pin(FixtureEventStream { receiver }))
    }

    async fn subscribe_channel_activity(
        &self,
        _request: openbot_application::ChannelActivitySubscription,
    ) -> Result<AppEventStream, ThreadDirectoryError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            _ = sender
                .send(AppEvent::ChannelActivity(ChannelActivityEvent {
                    channel_id: ChannelId::new("channel-00"),
                    last_message: Some("Categorized three expenses.".to_owned()),
                    last_message_at: Some(OffsetDateTime::now_utc()),
                    last_message_agent_id: Some(BotId::new("bot-0")),
                }))
                .await;
            // production `subscribe_channel_activity` 用 LISTEN/NOTIFY 长连保持该流打开。fixture
            // 若发完就 drop sender，流立刻结束、socket 关闭，AppSidebar 会以 reset 后的 backoff
            // 无限重连并对每次重连全量重取 channel 列表 —— 侧栏持续闪 "加载中"，那是 harness
            // 造出来的假象，不是被验收的 GUI 行为。持住 sender，让流像生产一样保持打开。
            std::future::pending::<()>().await;
        });
        Ok(Box::pin(FixtureEventStream { receiver }))
    }
}

struct FixtureEventStream {
    receiver: tokio::sync::mpsc::Receiver<AppEvent>,
}

impl Stream for FixtureEventStream {
    type Item = AppEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

struct FixtureAuthResolver {
    resolved: ResolvedAuth,
    revoked: AtomicBool,
}

#[async_trait]
impl AuthResolver for FixtureAuthResolver {
    async fn resolve(
        &self,
        _parts: &axum::http::request::Parts,
    ) -> Result<AuthContext, openbot_contracts::error::AppError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(openbot_contracts::error::AppError::Unauthenticated)
        } else {
            Ok(self.resolved.context().clone())
        }
    }

    async fn resolve_with_assurance(
        &self,
        _parts: &axum::http::request::Parts,
    ) -> Result<ResolvedAuth, openbot_contracts::error::AppError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(openbot_contracts::error::AppError::Unauthenticated)
        } else {
            Ok(self.resolved.clone())
        }
    }

    async fn revoke_session(
        &self,
        resolved: &ResolvedAuth,
    ) -> Result<(), openbot_contracts::error::AppError> {
        if !resolved.has_revocable_session() {
            return Err(openbot_contracts::error::AppError::RequestConflict {
                resource: "session",
            });
        }
        self.revoked.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone)]
struct FixtureApprovals {
    pending: Arc<Mutex<Option<PendingToolApproval>>>,
    subscribers: Arc<Mutex<Vec<tokio::sync::mpsc::Sender<AppEvent>>>>,
    list_calls: Arc<AtomicU64>,
    subscription_calls: Arc<AtomicU64>,
}

#[derive(Clone)]
struct FixtureApprovalProbe {
    list_calls: Arc<AtomicU64>,
    subscription_calls: Arc<AtomicU64>,
}

struct ApprovalFixtureAssembly {
    port: Arc<dyn ToolApprovalAdministration>,
    people: FixturePeoplePort,
    policy: PolicyStore,
    auth_resolver: Option<Arc<dyn AuthResolver>>,
    dynamic_sso: Option<Arc<DynamicSsoService>>,
    memory_probe: Option<FixtureApprovalProbe>,
    postgres_probe: Option<PostgresApprovalProbe>,
    session_bootstrap: bool,
    mode: &'static str,
    auth_mode: &'static str,
}

#[derive(Clone)]
struct PostgresApprovalProbe {
    pool: openbot_infra::db::pool::DatabasePool,
    waiter_state: Arc<AtomicU8>,
}

#[derive(Clone, Default)]
struct IdentityProviderHttpProbe {
    list: Arc<AtomicU64>,
    register: Arc<AtomicU64>,
    remove: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityProviderHttpOperation {
    List,
    Register,
    Remove,
}

#[derive(Default)]
struct FixturePreferences {
    stored: Mutex<UiPreferences>,
}

#[async_trait]
impl UiPreferenceAdministration for FixturePreferences {
    async fn get(
        &self,
        _auth: &AuthContext,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        self.stored
            .lock()
            .map(|stored| *stored)
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)
    }

    async fn update(
        &self,
        _auth: &AuthContext,
        update: UpdateUiPreferences,
    ) -> Result<UiPreferences, UiPreferenceAdministrationError> {
        // Keep the deterministic browser fixture slow enough to exercise the serialized/coalesced
        // client queue and its visible pending state across browser-control round trips instead of
        // letting loopback finish before the next assertion can observe it.
        tokio::time::sleep(std::time::Duration::from_millis(1_000)).await;
        let mut stored = self
            .stored
            .lock()
            .map_err(|_| UiPreferenceAdministrationError::Unavailable)?;
        let revision = match stored.revision {
            Some(current) if update.expected_revision != Some(current) => {
                return Err(UiPreferenceAdministrationError::StaleSnapshot(
                    stored.revision_snapshot().map_err(|_| {
                        UiPreferenceAdministrationError::Corrupt {
                            field: "preferences",
                        }
                    })?,
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
        stored.updated_at = Some(OffsetDateTime::UNIX_EPOCH);
        Ok(*stored)
    }
}

impl FixtureApprovals {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            pending: Arc::new(Mutex::new(Some(PendingToolApproval {
                approval_id: "approval-fixture-1".to_owned(),
                call_id: ToolCallId::new("call-fixture-1"),
                run_id: RunId::new("run-fixture-1"),
                bot_id: BotId::new("bot-fixture-1"),
                tool_name: "mcp__workspace__overwrite_report".to_owned(),
                target_kind: "mcp_tool".to_owned(),
                target_id: "workspace/reports/q4.txt".to_owned(),
                effect: ToolApprovalEffect::Write,
                approval_class: ToolApprovalClass::EveryCall,
                arguments_summary: serde_json::json!({
                    "path": "/reports/q4.txt",
                    "mode": "overwrite",
                    "credential": "[redacted]"
                }),
                change_summary: Some(serde_json::json!({
                    "kind": "replace",
                    "linesRemoved": 12,
                    "linesAdded": 18
                })),
                requested_at: now,
                expires_at: now + Duration::hours(1),
            }))),
            subscribers: Arc::new(Mutex::new(Vec::new())),
            list_calls: Arc::new(AtomicU64::new(0)),
            subscription_calls: Arc::new(AtomicU64::new(0)),
        }
    }

    fn probe(&self) -> FixtureApprovalProbe {
        FixtureApprovalProbe {
            list_calls: Arc::clone(&self.list_calls),
            subscription_calls: Arc::clone(&self.subscription_calls),
        }
    }
}

#[async_trait]
impl ToolApprovalAdministration for FixtureApprovals {
    async fn list_pending(
        &self,
        _auth: &AuthContext,
    ) -> Result<PendingToolApprovals, ToolApprovalAdministrationError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PendingToolApprovals {
            approvals: self
                .pending
                .lock()
                .map_err(|_| ToolApprovalAdministrationError::Unavailable)?
                .iter()
                .cloned()
                .collect(),
        })
    }

    async fn decide(
        &self,
        _auth: &AuthContext,
        approval_id: &str,
        decision: ToolApprovalDecision,
    ) -> Result<ToolApprovalResolved, ToolApprovalAdministrationError> {
        let subscribers = self
            .subscribers
            .lock()
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)?
            .clone();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| ToolApprovalAdministrationError::Unavailable)?;
            let Some(request) = pending.as_ref() else {
                return Err(ToolApprovalAdministrationError::NotVisible);
            };
            if request.approval_id != approval_id {
                return Err(ToolApprovalAdministrationError::NotVisible);
            }
            *pending = None;
        }
        for subscriber in subscribers {
            _ = subscriber
                .send(AppEvent::ToolApprovalActivity(ToolApprovalActivityEvent {
                    pending_count: 0,
                }))
                .await;
        }
        Ok(ToolApprovalResolved {
            approval_id: approval_id.to_owned(),
            decision,
        })
    }

    async fn subscribe_activity(
        &self,
        _auth: &AuthContext,
    ) -> Result<AppEventStream, ToolApprovalAdministrationError> {
        let pending_count = self
            .pending
            .lock()
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)
            .map(|pending| u32::from(pending.is_some()))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .try_send(AppEvent::ToolApprovalActivity(ToolApprovalActivityEvent {
                pending_count,
            }))
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)?;
        self.subscribers
            .lock()
            .map_err(|_| ToolApprovalAdministrationError::Unavailable)?
            .push(sender);
        self.subscription_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(FixtureEventStream { receiver }))
    }
}

async fn assemble_approval_fixture(
    now: OffsetDateTime,
    auth: &AuthContext,
) -> Result<ApprovalFixtureAssembly, Box<dyn Error>> {
    let database_url = match std::env::var(FIXTURE_APPROVAL_DATABASE_URL) {
        Ok(database_url) if !database_url.is_empty() => database_url,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{FIXTURE_APPROVAL_DATABASE_URL} must not be empty"),
            )
            .into());
        }
        Err(std::env::VarError::NotPresent) => {
            let approvals = FixtureApprovals::new(now);
            return Ok(ApprovalFixtureAssembly {
                auth_resolver: None,
                dynamic_sso: None,
                memory_probe: Some(approvals.probe()),
                postgres_probe: None,
                port: Arc::new(approvals),
                people: FixturePeoplePort::Memory(FixturePeople::new(now)),
                policy: PolicyStore::in_memory(None),
                session_bootstrap: false,
                mode: "memory",
                auth_mode: "fixed",
            });
        }
        Err(error) => return Err(error.into()),
    };

    let config = database_url.parse::<openbot_infra::db::pool::DatabaseConfig>()?;
    validate_fixture_database(&config)?;
    let database = pool::connect(&config).await?;
    let mut client = database.get().await?;
    baseline::apply(&client).await?;
    native::apply(&mut client).await?;
    seed_postgres_approval_scope(&mut client, now).await?;
    drop(client);

    let policy = PolicyStore::postgres(database.clone(), None);
    policy.load().await?;

    let coordinator = Arc::new(PostgresToolApprovalCoordinator::new(
        database.clone(),
        auth.deployment().clone(),
        auth.tenant().clone(),
        FIXTURE_APPROVAL_AUDIT_KEY.to_vec(),
    )?);
    let auth_resolver: Arc<dyn AuthResolver> = Arc::new(PostgresSessionAuthResolver::new(
        database.clone(),
        FIXTURE_SESSION_HASH_KEY,
        default_session_lifetime(),
        auth.deployment().clone(),
        auth.tenant().clone(),
    )?);
    let floor = AdminFloor::from_configured([FIXTURE_CONFIGURED_ADMIN_EMAIL])?;
    let dynamic_sso = Arc::new(DynamicSsoService::new(
        database.clone(),
        auth.tenant(),
        FIXTURE_SESSION_HASH_KEY,
        FIXTURE_SESSION_HASH_KEY,
        FIXTURE_APPROVAL_AUDIT_KEY,
        WrappingKey::from_bytes(vec![0x62; 32])?,
        KeyVersion::new(1),
        default_session_lifetime(),
        floor.clone(),
        [
            "google".to_owned(),
            "microsoft".to_owned(),
            "okta".to_owned(),
        ],
        SafeDialer::new(EgressPolicy::default()),
        FIXTURE_SSO_PUBLIC_URL.to_owned(),
    )?);
    let people = FixturePeoplePort::Postgres(PostgresPeopleAdministration::new(
        database.clone(),
        Some(floor),
        FIXTURE_APPROVAL_AUDIT_KEY.to_vec(),
    )?);
    let request = postgres_approval_request(auth)?;
    let waiter_state = Arc::new(AtomicU8::new(0));
    let waiter_coordinator = Arc::clone(&coordinator);
    let waiter_state_for_task = Arc::clone(&waiter_state);
    tokio::spawn(async move {
        let state = match waiter_coordinator.request_and_wait(&request).await {
            Ok(DurableHumanDecision::Granted { .. }) => {
                println!("OPENBOT_UI_APPROVAL_WAITER=granted");
                1
            }
            Ok(DurableHumanDecision::Denied) => {
                println!("OPENBOT_UI_APPROVAL_WAITER=denied");
                2
            }
            Err(error) => {
                tracing::error!(error = %error, "PostgreSQL approval fixture waiter failed");
                println!("OPENBOT_UI_APPROVAL_WAITER=failed");
                3
            }
        };
        waiter_state_for_task.store(state, Ordering::SeqCst);
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let pending = coordinator.list_pending(auth).await?;
            if !pending.approvals.is_empty() {
                return Ok::<(), ToolApprovalAdministrationError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| std::io::Error::other("PostgreSQL approval fixture did not become pending"))??;

    Ok(ApprovalFixtureAssembly {
        auth_resolver: Some(auth_resolver),
        dynamic_sso: Some(dynamic_sso),
        port: coordinator,
        people,
        policy,
        memory_probe: None,
        postgres_probe: Some(PostgresApprovalProbe {
            pool: database,
            waiter_state,
        }),
        session_bootstrap: true,
        mode: "postgres",
        auth_mode: "postgres_session",
    })
}

fn validate_fixture_database(
    config: &openbot_infra::db::pool::DatabaseConfig,
) -> Result<(), std::io::Error> {
    let name = config.dbname.as_str();
    if config.host != "127.0.0.1"
        || !name.starts_with(FIXTURE_APPROVAL_DATABASE_PREFIX)
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "approval fixture requires a loopback, explicitly prefixed database",
        ));
    }
    Ok(())
}

async fn seed_postgres_approval_scope(
    client: &mut openbot_infra::db::pool::PooledClient,
    now: OffsetDateTime,
) -> Result<(), tokio_postgres::Error> {
    let token_hash = SessionTokenHash::compute(
        SessionToken::new(FIXTURE_SESSION_TOKEN.as_bytes()),
        SessionHashKey::new(FIXTURE_SESSION_HASH_KEY),
    )
    .to_column_value();
    let transaction = client.transaction().await?;
    transaction
        .batch_execute(POSTGRES_APPROVAL_SEED_SQL)
        .await?;
    transaction
        .execute(
            "INSERT INTO public.sessions(
               id,user_id,token,expires_at,created_at,updated_at,auth_generation
             ) VALUES($1,$2,$3,$4,$5,$5,$6)",
            &[
                &FIXTURE_SESSION_ID,
                &FIXTURE_ACTOR,
                &token_hash,
                &(now + Duration::hours(1)),
                &(now - Duration::minutes(1)),
                &1_i64,
            ],
        )
        .await?;
    transaction.commit().await
}

fn postgres_approval_request(auth: &AuthContext) -> Result<ToolApprovalRequest, Box<dyn Error>> {
    if auth.deployment().as_str() != FIXTURE_DEPLOYMENT
        || auth.tenant().as_str() != FIXTURE_TENANT
        || auth.actor().as_str() != FIXTURE_ACTOR
        || auth.auth_generation() != AuthGeneration::new(1)
    {
        return Err(std::io::Error::other("fixture approval AuthContext drift").into());
    }
    let tool = ToolName::new("mcp__workspace__overwrite_report")
        .map_err(|_| std::io::Error::other("fixture approval tool name drift"))?;
    Ok(ToolApprovalRequest {
        call_id: ToolCallId::new(FIXTURE_PG_CALL),
        actor: auth.actor().clone(),
        auth_generation: auth.auth_generation(),
        bot: BotId::new(FIXTURE_PG_BOT),
        run: RunId::new(FIXTURE_PG_RUN),
        thread: ThreadId::new(FIXTURE_PG_THREAD),
        tool,
        args_hash: Sha256Digest::of(br#"{"path":"/reports/q4.txt","mode":"overwrite"}"#),
        target: ApprovalTarget {
            kind: "mcp_tool",
            id: "workspace/reports/q4.txt".to_owned(),
        },
        effect: Effect::Write,
        approval_class: ApprovalClass::EveryCall,
        computer_generation: ComputerGeneration::new(0),
        catalog_generation: CatalogGeneration::new(7),
        target_document_generation: None,
        policy_version: PolicyVersionTag::new("b".repeat(64)),
        presentation: ToolApprovalPresentation {
            arguments_summary: serde_json::json!({
                "path": "/reports/q4.txt",
                "mode": "overwrite",
                "credential": "[redacted]"
            }),
            change_summary: Some(serde_json::json!({
                "kind": "replace",
                "linesRemoved": 12,
                "linesAdded": 18
            })),
        },
    })
}

async fn postgres_approval_proof(
    probe: PostgresApprovalProbe,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let client = probe
        .pool
        .get()
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*)::bigint FROM public.tool_approvals),
               (SELECT count(*)::bigint FROM public.tool_approvals WHERE state='pending'),
               (SELECT count(*)::bigint FROM public.tool_approvals WHERE state='granted'),
               (SELECT count(*)::bigint FROM public.tool_approvals
                 WHERE state<>'pending' AND arguments_summary IS NULL AND change_summary IS NULL),
               (SELECT count(*)::bigint FROM public.audit_events
                 WHERE event_type='tool.approval_requested'),
               (SELECT count(*)::bigint FROM public.audit_events
                 WHERE event_type='tool.approval_granted'),
               (SELECT count(*)::bigint FROM public.sessions),
               (SELECT count(*)::bigint FROM public.sessions WHERE left(token,4)='sh1_')",
            &[],
        )
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    let value = |index| {
        row.try_get::<_, i64>(index)
            .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)
    };
    Ok(axum::Json(serde_json::json!({
        "mode": "postgres",
        "waiter": waiter_state_label(probe.waiter_state.load(Ordering::SeqCst)),
        "approvals": value(0)?,
        "pending": value(1)?,
        "granted": value(2)?,
        "summariesCleared": value(3)?,
        "requestedAudits": value(4)?,
        "grantedAudits": value(5)?,
        "sessions": value(6)?,
        "hashedSessions": value(7)?,
    })))
}

async fn postgres_identity_provider_proof(
    probe: PostgresApprovalProbe,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let client = probe
        .pool
        .get()
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*)::bigint FROM public.sso_providers),
               (SELECT count(*)::bigint FROM public.sso_providers
                 WHERE saml_config IS NOT NULL),
               (SELECT count(*)::bigint FROM public.sso_providers
                 WHERE saml_config LIKE '{\"version\":2%'),
               (SELECT count(*)::bigint FROM public.sso_providers
                 WHERE saml_config LIKE '%EntityDescriptor%'),
               (SELECT count(*)::bigint FROM public.audit_events
                 WHERE event_type='identity_provider.registered'),
               (SELECT count(*)::bigint FROM public.audit_events
                 WHERE event_type='identity_provider.removed')",
            &[],
        )
        .await
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)?;
    let value = |index| {
        row.try_get::<_, i64>(index)
            .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)
    };
    Ok(axum::Json(serde_json::json!({
        "providers": value(0)?,
        "samlConfigs": value(1)?,
        "v2Envelopes": value(2)?,
        "plaintextMetadata": value(3)?,
        "registeredAudits": value(4)?,
        "removedAudits": value(5)?,
    })))
}

async fn identity_provider_http_probe(
    probe: IdentityProviderHttpProbe,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "list": probe.list.load(Ordering::SeqCst),
        "register": probe.register.load(Ordering::SeqCst),
        "remove": probe.remove.load(Ordering::SeqCst),
    }))
}

async fn count_identity_provider_http(
    axum::extract::State(probe): axum::extract::State<IdentityProviderHttpProbe>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match identity_provider_http_operation(request.method(), request.uri().path()) {
        Some(IdentityProviderHttpOperation::List) => {
            probe.list.fetch_add(1, Ordering::SeqCst);
        }
        Some(IdentityProviderHttpOperation::Register) => {
            probe.register.fetch_add(1, Ordering::SeqCst);
        }
        Some(IdentityProviderHttpOperation::Remove) => {
            probe.remove.fetch_add(1, Ordering::SeqCst);
        }
        None => {}
    }
    next.run(request).await
}

fn identity_provider_http_operation(
    method: &axum::http::Method,
    path: &str,
) -> Option<IdentityProviderHttpOperation> {
    match (method, path) {
        (&axum::http::Method::GET, "/api/admin/identity-providers") => {
            Some(IdentityProviderHttpOperation::List)
        }
        (&axum::http::Method::POST, "/api/auth/sso/register") => {
            Some(IdentityProviderHttpOperation::Register)
        }
        (&axum::http::Method::DELETE, path)
            if path.starts_with("/api/admin/identity-providers/") =>
        {
            Some(IdentityProviderHttpOperation::Remove)
        }
        _ => None,
    }
}

const fn waiter_state_label(state: u8) -> &'static str {
    match state {
        0 => "waiting",
        1 => "granted",
        2 => "denied",
        _ => "failed",
    }
}

async fn fixture_session_start() -> Result<axum::response::Response, axum::http::StatusCode> {
    let cookie = axum::http::HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={FIXTURE_SESSION_TOKEN}; Path=/; HttpOnly; SameSite=Lax"
    ))
    .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut response = axum::response::Redirect::to("/approvals").into_response();
    response
        .headers_mut()
        .insert(axum::http::header::SET_COOKIE, cookie);
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

fn auth_journey_enabled() -> Result<bool, Box<dyn Error>> {
    match std::env::var(FIXTURE_AUTH_JOURNEY_ENV) {
        Ok(value) if value == "1" => Ok(true),
        Ok(_) => Err(format!("{FIXTURE_AUTH_JOURNEY_ENV} must be exactly 1 when present").into()),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn home_skills_fixture_enabled(value: Option<&std::ffi::OsStr>) -> Result<bool, std::io::Error> {
    match value {
        None => Ok(false),
        Some(value) if value == std::ffi::OsStr::new("1") => Ok(true),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OPENBOT_UI_HOME_SKILLS_FIXTURE must be exactly 1 when present",
        )),
    }
}

fn validate_home_skills_fixture_mode(
    enabled: bool,
    approval_mode: &str,
    auth_mode: &str,
    auth_journey: bool,
) -> Result<(), std::io::Error> {
    if enabled && (approval_mode != "memory" || auth_mode != "fixed" || auth_journey) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Synthetic Home skills require Memory/fixed mode without the auth journey",
        ));
    }
    Ok(())
}

async fn auth_journey_middleware(
    axum::extract::State(probe): axum::extract::State<AuthJourneyProbe>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header::{CACHE_CONTROL, COOKIE, SET_COOKIE};
    use axum::http::{HeaderValue, Method, StatusCode};

    let method = request.method().clone();
    let path = request.uri().path();
    if path == "/api/me" {
        probe.me_requests.fetch_add(1, Ordering::SeqCst);
        return next.run(request).await;
    }
    if method == Method::GET && path == "/api/capabilities" {
        probe.capability_requests.fetch_add(1, Ordering::SeqCst);
        let mut response = axum::Json(AuthenticationCapabilities {
            mode: ApplicationRuntimeMode::Rust,
            durable_history: true,
            auth_providers: vec![
                AuthProviderId::Google,
                AuthProviderId::Microsoft,
                AuthProviderId::Okta,
            ],
            sso_configured: true,
        })
        .into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    if method == Method::POST
        && matches!(
            path,
            "/api/auth/oidc/google/start"
                | "/api/auth/oidc/microsoft/start"
                | "/api/auth/oidc/okta/start"
        )
    {
        probe.oidc_start_requests.fetch_add(1, Ordering::SeqCst);
        let mut response = (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({"code":"authentication_unavailable"})),
        )
            .into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    if method == Method::POST && path == "/api/auth/sso/start" {
        probe
            .enterprise_start_requests
            .fetch_add(1, Ordering::SeqCst);
        let mut response = (
            StatusCode::ACCEPTED,
            axum::Json(EnterpriseSsoRoutingAccepted { accepted: true }),
        )
            .into_response();
        response.headers_mut().insert(
            SET_COOKIE,
            HeaderValue::from_static(
                "openbot_sso_route=fixture-auth-route; Path=/; HttpOnly; SameSite=Lax",
            ),
        );
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    if method == Method::GET && path == "/api/auth/sso/continue" {
        probe
            .enterprise_continue_requests
            .fetch_add(1, Ordering::SeqCst);
        let has_ticket = request
            .headers()
            .get(COOKIE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .map(str::trim)
                    .any(|cookie| cookie == FIXTURE_SSO_ROUTE_COOKIE)
            });
        if !has_ticket {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let mut response =
            axum::response::Redirect::to("/sign?fixture-sso=continued").into_response();
        response.headers_mut().insert(
            SET_COOKIE,
            HeaderValue::from_static(
                "openbot_sso_route=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            ),
        );
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    if is_auth_journey_protected_path(path) {
        probe.protected_requests.fetch_add(1, Ordering::SeqCst);
    }
    next.run(request).await
}

fn is_auth_journey_protected_path(path: &str) -> bool {
    [
        "/api/channels",
        "/api/agents",
        "/api/route",
        "/api/threads",
        "/api/tool-approvals",
        "/api/components",
        "/api/sandboxed",
        "/api/memories",
        "/api/me/preferences",
        "/api/admin",
    ]
    .iter()
    .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (dist, port) = arguments()?;
    let auth_journey = auth_journey_enabled()?;
    let home_skills_fixture =
        home_skills_fixture_enabled(std::env::var_os(FIXTURE_HOME_SKILLS_ENV).as_deref())?;
    let model_picker_fixture = fixture_model_connections::enabled(
        std::env::var_os(fixture_model_connections::ENV).as_deref(),
    )?;
    // Reject the opt-in before PostgreSQL assembly or any listening socket.
    validate_home_skills_fixture_mode(
        home_skills_fixture,
        if std::env::var_os(FIXTURE_APPROVAL_DATABASE_URL).is_some() {
            "postgres"
        } else {
            "memory"
        },
        "fixed",
        auth_journey,
    )?;
    // Reject this synthetic opt-in before PostgreSQL assembly or a listening socket.
    fixture_model_connections::validate_mode(
        model_picker_fixture,
        if std::env::var_os(FIXTURE_APPROVAL_DATABASE_URL).is_some() {
            "postgres"
        } else {
            "memory"
        },
        "fixed",
        auth_journey,
    )?;
    let now = OffsetDateTime::now_utc();
    let generation = AuthGeneration::new(1);
    let tenant = TenantId::new(FIXTURE_TENANT);
    let actor = ActorId::new(FIXTURE_ACTOR);
    let context = AuthContext::for_test(
        DeploymentId::new(FIXTURE_DEPLOYMENT),
        tenant.clone(),
        actor.clone(),
        [Role::User, Role::Admin],
        generation,
        false,
    );
    let ApprovalFixtureAssembly {
        port: approvals,
        people,
        policy,
        auth_resolver,
        dynamic_sso,
        memory_probe: approval_probe,
        postgres_probe,
        session_bootstrap,
        mode: approval_mode,
        auth_mode,
    } = assemble_approval_fixture(now, &context).await?;
    validate_home_skills_fixture_mode(home_skills_fixture, approval_mode, auth_mode, auth_journey)?;
    fixture_model_connections::validate_mode(
        model_picker_fixture,
        approval_mode,
        auth_mode,
        auth_journey,
    )?;
    let home_skills_context = home_skills_fixture.then(|| context.clone());
    let lifetime = default_session_lifetime();
    let resolver: Arc<dyn AuthResolver> = match auth_resolver {
        Some(resolver) => resolver,
        None => {
            let live = evaluate_session(
                lifetime,
                SessionState::rehydrate(now - Duration::minutes(1), now, generation),
                generation,
                now,
            )?;
            Arc::new(FixtureAuthResolver {
                resolved: ResolvedAuth::from_live_session(
                    context,
                    live,
                    Some("fixture-session".to_owned()),
                ),
                revoked: AtomicBool::new(false),
            })
        }
    };
    let channels = FixtureChannels::new(now);
    if model_picker_fixture {
        // An empty channel makes the explicit ModelPicker fixture reachable without a run.
        channels.rows.lock().expect("fixture channel lock").insert(
            0,
            ChannelSummary {
                id: ChannelId::new("channel-model-picker-fixture"),
                name: "Model picker fixture conversation".to_owned(),
                agent_ids: vec![BotId::new("fixture-owned-public")],
                last_message: None,
                last_message_at: None,
                last_message_agent_id: None,
                created_at: now,
                thread_id: None,
                active: true,
            },
        );
    }
    let home_channel_probe = channels.clone();
    let threads = FixtureThreads::new(channels.clone());
    let bot_thread_probe = threads.clone();
    let memory = FixtureMemory::new(tenant, actor.clone(), now);
    let connections = FixtureConnections::new(actor, port, now);
    let components = FixtureComponents::new(now, threads.clone());
    let sandboxed = FixtureSandboxed::new(now);
    let routing = FixtureRouting::new();
    let routing_probe = routing.probe();
    let agents = Arc::new(FixtureAgents::new());
    let plugins = fixture_plugins::PluginsFixture::new(connections);
    let plugins = match home_skills_context.as_ref() {
        Some(context) => plugins.with_home_skills(context),
        None => plugins,
    };
    let credentials = fixture_credentials::assemble(postgres_probe.as_ref())?;
    let mut application = OpenBotApplication::new(channels.clone())
        .with_channel_administration(Arc::new(channels))
        .with_audit(FixtureAudit::new(now))
        .with_agent_callback_tokens((*agents).clone())
        .with_agent_directory(agents.clone())
        .with_agent_administration(agents)
        .with_channel_routing(Arc::new(routing))
        .with_component_administration(Arc::new(components))
        .with_sandboxed_component_administration(Arc::new(sandboxed))
        .with_people(people)
        .with_policy(policy)
        .with_threads(threads)
        .with_memory(memory)
        .with_mcp_connections(Arc::new(plugins.clone()))
        .with_credentials(credentials)
        .with_tool_approvals(approvals)
        .with_ui_preferences(Arc::new(FixturePreferences::default()));
    if model_picker_fixture {
        application = application.with_model_connections(Arc::new(
            fixture_model_connections::FixtureModelConnections::new(),
        ));
    }
    let application: Arc<dyn ApplicationService> = Arc::new(application);
    let origin = format!("http://127.0.0.1:{port}");
    let mut builder = ServerBuilder::new(application, resolver)
        .with_sensitive_write_security(SensitiveWriteSecurity::new(
            lifetime,
            TrustedOrigins::from_configured([origin.as_str()])?,
        ))
        .with_static_app(StaticApp::open(dist)?);
    if let Some(dynamic_sso) = dynamic_sso {
        builder = builder.with_dynamic_sso(dynamic_sso);
    }
    let mut router = builder.into_router();
    let plugin_probe = plugins.clone();
    router = router.route(
        "/__fixture/plugins/proof",
        axum::routing::get(move || {
            let fixture = plugin_probe.clone();
            async move { axum::Json(fixture.proof()) }
        }),
    );
    router = router.route(
        "/__fixture/plugins/control",
        axum::routing::post(move |axum::Json(mode): axum::Json<u8>| {
            let fixture = plugins.clone();
            async move {
                if fixture.control(mode) {
                    axum::http::StatusCode::NO_CONTENT
                } else {
                    axum::http::StatusCode::BAD_REQUEST
                }
            }
        }),
    );
    if let Some(approval_probe) = approval_probe {
        router = router.route(
            "/__fixture/approval-probe",
            axum::routing::get(move || {
                let probe = approval_probe.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "listCalls": probe.list_calls.load(Ordering::SeqCst),
                        "subscriptionCalls": probe.subscription_calls.load(Ordering::SeqCst),
                    }))
                }
            }),
        );
    }
    if let Some(postgres_probe) = postgres_probe {
        let identity_provider_probe = postgres_probe.clone();
        router = router.route(
            "/api/__fixture/approval-pg-proof",
            axum::routing::get(move || {
                let probe = postgres_probe.clone();
                async move { postgres_approval_proof(probe).await }
            }),
        );
        router = router.route(
            "/api/__fixture/identity-provider-pg-proof",
            axum::routing::get(move || {
                let probe = identity_provider_probe.clone();
                async move { postgres_identity_provider_proof(probe).await }
            }),
        );
    }
    if session_bootstrap {
        router = router.route(
            "/api/__fixture/session/start",
            axum::routing::get(fixture_session_start),
        );
    }
    let routing_probe_route = routing_probe.clone();
    let routing_failure_probe = routing_probe.clone();
    router = router.route(
        "/api/__fixture/home-routing-proof",
        axum::routing::get(move || {
            let probe = routing_probe_route.clone();
            async move { fixture_routing_probe(probe).await }
        }),
    );
    router = router.route(
        "/api/__fixture/home-routing/fail-next-record",
        axum::routing::post(move || {
            let probe = routing_failure_probe.clone();
            async move { fixture_fail_next_routing_record(probe).await }
        }),
    );
    router = router.route(
        "/api/__fixture/home-proof",
        axum::routing::get(move || {
            let channels = home_channel_probe.clone();
            let routing = routing_probe.clone();
            async move { fixture_home_probe(channels, routing).await }
        }),
    );
    router = router.route(
        "/api/__fixture/bot-proof",
        axum::routing::get(move || {
            let threads = bot_thread_probe.clone();
            async move {
                threads
                    .proof()
                    .map(axum::Json)
                    .map_err(|()| axum::http::StatusCode::SERVICE_UNAVAILABLE)
            }
        }),
    );
    let identity_provider_http = IdentityProviderHttpProbe::default();
    let identity_provider_http_route = identity_provider_http.clone();
    router = router.route(
        "/api/__fixture/identity-provider-http-proof",
        axum::routing::get(move || {
            let probe = identity_provider_http_route.clone();
            async move { identity_provider_http_probe(probe).await }
        }),
    );
    router = router.layer(axum::middleware::from_fn_with_state(
        identity_provider_http,
        count_identity_provider_http,
    ));
    if auth_journey {
        let auth_probe = AuthJourneyProbe::default();
        let proof_probe = auth_probe.clone();
        router = router.route(
            "/api/__fixture/auth-proof",
            axum::routing::get(move || {
                let probe = proof_probe.clone();
                async move { axum::Json(probe.proof()) }
            }),
        );
        router = router.layer(axum::middleware::from_fn_with_state(
            auth_probe,
            auth_journey_middleware,
        ));
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("OPENBOT_UI_APPROVAL_MODE={approval_mode}");
    println!("OPENBOT_UI_AUTH_MODE={auth_mode}");
    println!("OPENBOT_UI_AUTH_JOURNEY={auth_journey}");
    if home_skills_fixture {
        println!("OPENBOT_UI_HOME_SKILLS_FIXTURE=1");
        println!("OPENBOT_UI_HOME_SKILLS_PROVENANCE=Synthetic");
    }
    if model_picker_fixture {
        println!("OPENBOT_UI_MODEL_PICKER_FIXTURE=1");
        println!("OPENBOT_UI_MODEL_PICKER_PROVENANCE=Synthetic");
    }
    println!("OPENBOT_UI_FIXTURE_URL={origin}/approvals");
    axum::serve(listener, router).await?;
    Ok(())
}

fn arguments() -> Result<(String, u16), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let mut dist = None;
    let mut port = 39015_u16;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--dist" => dist = arguments.next(),
            "--port" => {
                port = arguments.next().ok_or("--port requires a value")?.parse()?;
            }
            _ => return Err(format!("unknown argument `{argument}`").into()),
        }
    }
    let dist = dist.ok_or("--dist is required")?;
    Ok((dist, port))
}

#[cfg(test)]
mod approval_pg_tests {
    use super::*;
    use openbot_domain::policy::{ActionPolicy, PolicyMode};
    use openbot_domain::routing::RoutingReasonCode;

    #[test]
    fn home_skills_fixture_flag_is_absent_or_exact_one_without_echoing_rejected_values() {
        use std::ffi::OsStr;

        assert!(!home_skills_fixture_enabled(None).unwrap());
        assert!(home_skills_fixture_enabled(Some(OsStr::new("1"))).unwrap());
        for value in ["", "0", "true", " 1", "1\n", "private-value-canary"] {
            let error = home_skills_fixture_enabled(Some(OsStr::new(value))).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "OPENBOT_UI_HOME_SKILLS_FIXTURE must be exactly 1 when present"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn home_skills_fixture_flag_rejects_non_unicode_without_disclosing_it() {
        use std::os::unix::ffi::OsStrExt;

        let error =
            home_skills_fixture_enabled(Some(std::ffi::OsStr::from_bytes(b"\xff"))).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "OPENBOT_UI_HOME_SKILLS_FIXTURE must be exactly 1 when present"
        );
    }

    #[test]
    fn home_skills_fixture_opt_in_requires_memory_fixed_without_auth_journey() {
        assert!(validate_home_skills_fixture_mode(true, "memory", "fixed", false).is_ok());
        for (approval, auth, journey) in [
            ("postgres", "fixed", false),
            ("memory", "session", false),
            ("memory", "fixed", true),
            ("private-mode-canary", "private-auth-canary", false),
        ] {
            let error =
                validate_home_skills_fixture_mode(true, approval, auth, journey).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(
                error.to_string(),
                "Synthetic Home skills require Memory/fixed mode without the auth journey"
            );
            // None leaves every existing assembly mode under its original startup validation.
            assert!(validate_home_skills_fixture_mode(false, approval, auth, journey).is_ok());
        }
    }

    #[tokio::test]
    async fn agent_callback_fixture_rotates_and_revokes_one_time_values() {
        let agents = FixtureAgents::new();
        let auth = AuthContext::for_test(
            DeploymentId::new(FIXTURE_DEPLOYMENT),
            TenantId::new(FIXTURE_TENANT),
            ActorId::new(FIXTURE_ACTOR),
            [Role::User],
            AuthGeneration::new(1),
            false,
        );
        let agent_id = BotId::new("fixture-owned-private");

        let first = agents.issue(&auth, &agent_id).await.unwrap();
        let second = agents.issue(&auth, &agent_id).await.unwrap();
        assert!(first.expose().starts_with("obot_agt_"));
        assert_ne!(first, second);
        assert!(
            agents
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|profile| profile.id == agent_id)
                .unwrap()
                .has_callback_token
        );

        assert_eq!(
            agents.revoke(&auth, &agent_id).await.unwrap(),
            CallbackTokenRevoked
        );
        assert!(
            !agents
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|profile| profile.id == agent_id)
                .unwrap()
                .has_callback_token
        );

        let wrong_actor = AuthContext::for_test(
            DeploymentId::new(FIXTURE_DEPLOYMENT),
            TenantId::new(FIXTURE_TENANT),
            ActorId::new("not-the-fixture-actor"),
            [Role::Admin],
            AuthGeneration::new(1),
            false,
        );
        assert_eq!(
            agents.issue(&wrong_actor, &agent_id).await.unwrap_err(),
            AgentCallbackTokenError::NotVisible
        );
    }

    #[tokio::test]
    async fn direct_bot_fixture_distinguishes_minted_from_persisted_threads() {
        let threads = FixtureThreads::new(FixtureChannels::new(OffsetDateTime::now_utc()));
        let deployment = DeploymentId::new(FIXTURE_DEPLOYMENT);
        let tenant = TenantId::new(FIXTURE_TENANT);
        let actor = ActorId::new(FIXTURE_ACTOR);
        let thread = threads.mint_thread_id(&deployment).await.unwrap();
        assert!(
            !threads
                .thread_known(&deployment, &tenant, &actor, &thread)
                .await
                .unwrap()
        );
        assert_eq!(
            threads
                .thread_conversation(ThreadConversationRequest {
                    deployment: deployment.clone(),
                    tenant: tenant.clone(),
                    actor: actor.clone(),
                    thread: thread.clone(),
                })
                .await,
            Err(ThreadDirectoryError::NotVisible)
        );

        threads
            .begin_thread_run(BeginThreadRunRequest {
                auth_generation: openbot_contracts::auth::AuthGeneration::new(0),
                deployment,
                tenant,
                actor,
                command: openbot_contracts::command::BeginThreadRun {
                    model_selection: None,
                    selected_skill_slugs: Vec::new(),
                    thread_id: thread,
                    run_id: RunId::new("fixture-direct-run"),
                    bot_id: BotId::new("fixture-owned-private"),
                    anchor: ThreadRunAnchor::DirectBot,
                    message: "fixture direct message".to_owned(),
                },
            })
            .await
            .unwrap();
        let proof = threads.proof().unwrap();
        assert_eq!(proof["mintCalls"], 1);
        assert_eq!(proof["statusChecks"], 1);
        assert_eq!(proof["conversationReads"], 1);
        assert_eq!(proof["directRuns"], 1);
        assert_eq!(proof["directThreads"], 1);
        assert_eq!(proof["persistedDirectThreads"], 1);
        assert_eq!(proof["lastBotId"], "fixture-owned-private");
        assert_eq!(proof["lastMessages"], 1);
        assert_eq!(proof["lastActive"], true);
        assert!(!proof.to_string().contains("fixture direct message"));
    }

    #[tokio::test]
    async fn home_routing_fixture_records_closed_facts_and_can_force_one_audit_failure() {
        let routing = FixtureRouting::new();
        let probe = routing.probe();
        let completion = routing.complete("ordinary routing prompt").await.unwrap();
        assert!(completion.contains("fixture-explore-public"));
        assert_eq!(
            routing
                .reachable_systems(&[BotId::new("fixture-system-public")])
                .await
                .unwrap()
                .len(),
            1
        );
        let inferred = RoutingAuditRecord {
            tenant: TenantId::new(FIXTURE_TENANT),
            actor: ActorId::new(FIXTURE_ACTOR),
            admin: true,
            roster: vec![BotId::new("fixture-system-public")],
            chosen: BotId::new("fixture-explore-public"),
            reason: RoutingReasonCode::ModelMatch,
            fallback: false,
            via_mention: false,
            candidates: vec![BotId::new("fixture-explore-public")],
        };
        routing.record_routing(inferred).await.unwrap();

        let explicit = RoutingAuditRecord {
            tenant: TenantId::new(FIXTURE_TENANT),
            actor: ActorId::new(FIXTURE_ACTOR),
            admin: true,
            roster: vec![BotId::new("fixture-system-public")],
            chosen: BotId::new("fixture-system-public"),
            reason: RoutingReasonCode::ExplicitChoice,
            fallback: false,
            via_mention: true,
            candidates: vec![BotId::new("fixture-system-public")],
        };
        routing.record_routing(explicit).await.unwrap();

        assert_eq!(
            routing
                .complete(&format!("prompt {FIXTURE_ROUTING_FALLBACK_CANARY}"))
                .await,
            Err(ChannelRoutingBackendError::Unavailable)
        );
        let failed = RoutingAuditRecord {
            tenant: TenantId::new(FIXTURE_TENANT),
            actor: ActorId::new(FIXTURE_ACTOR),
            admin: true,
            roster: vec![BotId::new("fixture-system-public")],
            chosen: BotId::new("fixture-system-public"),
            reason: RoutingReasonCode::RouterUnavailable,
            fallback: true,
            via_mention: false,
            candidates: vec![BotId::new("fixture-system-public")],
        };
        assert_eq!(
            routing.record_routing(failed).await,
            Err(ChannelRoutingBackendError::Unavailable)
        );

        let proof = fixture_routing_probe(probe).await.0;
        assert_eq!(proof["completeCalls"], 2);
        assert_eq!(proof["reachCalls"], 1);
        assert_eq!(proof["recordAttempts"], 3);
        assert_eq!(proof["recorded"], 2);
        assert_eq!(proof["explicit"], 1);
        assert_eq!(proof["inferred"], 1);
        assert_eq!(proof["failedRecords"], 1);
        assert_eq!(proof["lastChosen"], "fixture-system-public");
        assert!(!proof.to_string().contains(FIXTURE_ROUTING_FALLBACK_CANARY));
    }

    #[test]
    fn identity_provider_http_probe_counts_only_the_three_product_surfaces() {
        for (method, path, expected) in [
            (
                axum::http::Method::GET,
                "/api/admin/identity-providers",
                Some(IdentityProviderHttpOperation::List),
            ),
            (
                axum::http::Method::POST,
                "/api/auth/sso/register",
                Some(IdentityProviderHttpOperation::Register),
            ),
            (
                axum::http::Method::DELETE,
                "/api/admin/identity-providers/acme-saml",
                Some(IdentityProviderHttpOperation::Remove),
            ),
        ] {
            assert_eq!(identity_provider_http_operation(&method, path), expected);
        }
        for (method, path) in [
            (axum::http::Method::GET, "/api/admin/status"),
            (axum::http::Method::POST, "/api/auth/sso/update-provider"),
            (
                axum::http::Method::GET,
                "/api/__fixture/identity-provider-http-proof",
            ),
        ] {
            assert_eq!(identity_provider_http_operation(&method, path), None);
        }
    }

    #[test]
    fn auth_journey_probe_counts_only_auth_and_protected_product_surfaces() {
        let probe = AuthJourneyProbe::default();
        probe.me_requests.store(2, Ordering::SeqCst);
        probe.capability_requests.store(1, Ordering::SeqCst);
        probe.protected_requests.store(3, Ordering::SeqCst);
        assert_eq!(
            probe.proof(),
            serde_json::json!({
                "meRequests":2,
                "capabilityRequests":1,
                "oidcStartRequests":0,
                "enterpriseStartRequests":0,
                "enterpriseContinueRequests":0,
                "protectedRequests":3,
            })
        );
        for protected in [
            "/api/channels",
            "/api/channels/channel-1",
            "/api/agents",
            "/api/me/preferences",
            "/api/admin/status",
        ] {
            assert!(is_auth_journey_protected_path(protected), "{protected}");
        }
        for anonymous in [
            "/api/me",
            "/api/capabilities",
            "/api/auth/sso/start",
            "/api/__fixture/auth-proof",
        ] {
            assert!(!is_auth_journey_protected_path(anonymous), "{anonymous}");
        }
    }

    fn auth() -> AuthContext {
        AuthContext::for_test(
            DeploymentId::new(FIXTURE_DEPLOYMENT),
            TenantId::new(FIXTURE_TENANT),
            ActorId::new(FIXTURE_ACTOR),
            [Role::User, Role::Admin],
            AuthGeneration::new(1),
            false,
        )
    }

    #[test]
    fn postgres_request_seed_and_proof_states_are_one_closed_fixture_contract() {
        for identity in [
            FIXTURE_DEPLOYMENT,
            FIXTURE_TENANT,
            FIXTURE_ACTOR,
            FIXTURE_PG_BOT,
            FIXTURE_PG_THREAD,
            FIXTURE_PG_RUN,
        ] {
            assert!(POSTGRES_APPROVAL_SEED_SQL.contains(identity));
        }
        let request = postgres_approval_request(&auth()).expect("closed fixture request");
        assert_eq!(request.actor, ActorId::new(FIXTURE_ACTOR));
        assert_eq!(request.bot, BotId::new(FIXTURE_PG_BOT));
        assert_eq!(request.thread, ThreadId::new(FIXTURE_PG_THREAD));
        assert_eq!(request.run, RunId::new(FIXTURE_PG_RUN));
        assert_eq!(request.call_id, ToolCallId::new(FIXTURE_PG_CALL));
        assert_eq!(request.effect, Effect::Write);
        assert_eq!(request.approval_class, ApprovalClass::EveryCall);
        assert_eq!(
            request.presentation.arguments_summary["credential"],
            "[redacted]"
        );
        assert_eq!(waiter_state_label(0), "waiting");
        assert_eq!(waiter_state_label(1), "granted");
        assert_eq!(waiter_state_label(2), "denied");
        assert_eq!(waiter_state_label(3), "failed");

        let valid = openbot_infra::db::pool::DatabaseConfig::new(
            "127.0.0.1",
            5432,
            "postgres",
            "openbot_ui_approval_fixture_test",
        );
        assert!(validate_fixture_database(&valid).is_ok());
        assert!(validate_fixture_database(&valid.clone().with_dbname("postgres")).is_err());
        let remote = openbot_infra::db::pool::DatabaseConfig::new(
            "db.example.test",
            5432,
            "postgres",
            "openbot_ui_approval_fixture_test",
        );
        assert!(validate_fixture_database(&remote).is_err());

        let token_hash = SessionTokenHash::compute(
            SessionToken::new(FIXTURE_SESSION_TOKEN.as_bytes()),
            SessionHashKey::new(FIXTURE_SESSION_HASH_KEY),
        )
        .to_column_value();
        assert!(token_hash.starts_with("sh1_"));
        assert!(!token_hash.contains(FIXTURE_SESSION_TOKEN));
        assert!(!POSTGRES_APPROVAL_SEED_SQL.contains(FIXTURE_SESSION_TOKEN));
        assert!(
            POSTGRES_APPROVAL_SEED_SQL.contains("actor.id == \"fixture-actor\""),
            "PG fixture must exercise custom-allow preservation",
        );
    }

    #[tokio::test]
    async fn session_bootstrap_is_host_only_http_only_lax_no_store_redirect() {
        let response = fixture_session_start().await.expect("fixture redirect");
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[axum::http::header::LOCATION],
            "/approvals"
        );
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
        let cookie = response.headers()[axum::http::header::SET_COOKIE]
            .to_str()
            .expect("ASCII fixture cookie");
        assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}={FIXTURE_SESSION_TOKEN};")));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Domain="));
        assert!(!cookie.contains("Secure"));
    }

    #[tokio::test]
    async fn memory_people_fixture_is_paged_searchable_mutable_and_keeps_locked_rows() {
        let people = FixturePeople::new(OffsetDateTime::UNIX_EPOCH);
        let first = people
            .list_people(PeoplePageRequest {
                search: None,
                cursor: None,
                limit: 50,
            })
            .await
            .expect("fixture first page");
        assert_eq!(first.people.len(), 50);
        assert_eq!(
            first.next_cursor.as_deref(),
            Some("fixture-people-offset-50")
        );
        let second = people
            .list_people(PeoplePageRequest {
                search: None,
                cursor: first.next_cursor,
                limit: 50,
            })
            .await
            .expect("fixture second page");
        assert_eq!(second.people.len(), 2);
        assert!(second.next_cursor.is_none());
        let searched = people
            .list_people(PeoplePageRequest {
                search: Some("search target".to_owned()),
                cursor: None,
                limit: 50,
            })
            .await
            .expect("server-side fixture search");
        assert_eq!(searched.people[0].id, ActorId::new("fixture-search-target"));

        let target = ActorId::new("fixture-person-04");
        let promoted = people
            .change_role(&ActorId::new(FIXTURE_ACTOR), &target, Role::Admin)
            .await
            .expect("target promotion");
        assert_eq!(promoted.role, Role::Admin);
        let removed = people
            .change_access(&ActorId::new(FIXTURE_ACTOR), &target, true)
            .await
            .expect("target removal");
        assert!(removed.revoked);
        assert_eq!(
            people
                .change_role(
                    &ActorId::new(FIXTURE_ACTOR),
                    &ActorId::new("fixture-configured-admin"),
                    Role::User,
                )
                .await
                .unwrap_err(),
            PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::RoleConfiguredAdmin,
            },
        );
        assert_eq!(
            people
                .change_access(
                    &ActorId::new(FIXTURE_ACTOR),
                    &ActorId::new(FIXTURE_ACTOR),
                    true,
                )
                .await
                .unwrap_err(),
            PeoplePortError::IdentityConflict {
                reason: IdentityConflictReason::AccessSelfRevocation,
            },
        );
    }

    #[tokio::test]
    async fn memory_policy_fixture_starts_unconfigured_then_keeps_the_explicit_preset() {
        let store = PolicyStore::in_memory(None);
        assert!(store.current().is_none());
        store
            .set(
                ActionPolicy {
                    mode: PolicyMode::Enforce,
                    deny: Vec::new(),
                    allow: vec!["true".to_owned()],
                },
                Some(FIXTURE_ACTOR),
            )
            .await
            .expect("fixture policy preset");
        let stored = store.current().expect("explicit fixture policy");
        assert_eq!(stored.mode, PolicyMode::Enforce);
        assert!(stored.deny.is_empty());
        assert_eq!(stored.allow, ["true"]);
    }
}
