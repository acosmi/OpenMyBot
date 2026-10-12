//! PostgreSQL compiled-component governance projection and additive build catalogue sync.

use crate::db::pool::DatabasePool as Pool;
use async_trait::async_trait;
use openbot_application::{
    ComponentAdministration, ComponentAdministrationError, ComponentFunctionArguments,
    ComponentFunctionCallPlan, ComponentHumanDecisionDraft, ComponentHumanDecisionScope,
    ComponentRuntimeScope, validate_manifest_entries,
};
use openbot_contracts::agent::AgentVisibility;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::components::{
    AUDIT_TRAIL_READS_DESCRIPTION, BOT_ACTIVITY_FUNCTION_NAME, BotActivityReport, BotActivityRow,
    CompiledComponentKind, CompiledComponentManifestEntry, ComponentCatalogueAdded,
    ComponentDecision, ComponentDecisionRefusal, ComponentFunctionCall, ComponentFunctionData,
    ComponentFunctionError, ComponentGovernanceMutation, ComponentHumanDecisionAnswer,
    ComponentHumanDecisionResolved, ComponentRecord, ComponentRecords, GrantedCompiledComponent,
    GrantedCompiledComponents, MAX_COMPONENT_DESCRIPTION_BYTES, PendingComponentHumanDecision,
    PendingComponentHumanDecisions, RECENT_REFUSALS_FUNCTION_NAME, RecentRefusalRow,
    RecentRefusalsReport, component_data_function_manifest,
    validate_component_human_decision_answer,
};
use openbot_domain::agent::profile_policy::{AgentActor, AgentProfileFacts, can_run_agent};
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::hash::Sha256Digest;
use openbot_domain::audit::payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::components::{
    ComponentGrantDecision, ComponentGrantFacts, ComponentGrantRefusal,
    decide_component_function_grant, decide_component_grant,
};
use openbot_domain::policy::{ActorRef, BotRef, Intent, PageRef, PolicyContext, ToolRef, evaluate};
use openbot_domain::vault::SecretBytes;
use tokio_postgres::{IsolationLevel, Row, Transaction};

use crate::policy::PolicyStore;
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};

const HUMAN_DECISION_POLL_INTERVAL: core::time::Duration = core::time::Duration::from_secs(1);

/// Production PostgreSQL adapter for compiled-component read/sync operations.
pub struct PostgresComponentAdministration {
    pool: Pool,
    checkpoint_key: SecretBytes,
    policy: PolicyStore,
}

impl PostgresComponentAdministration {
    /// Construct with the deployment's existing domain-separated audit checkpoint key.
    pub fn new(pool: Pool, checkpoint_key: Vec<u8>) -> Result<Self, ComponentAdministrationError> {
        if checkpoint_key.is_empty() {
            return Err(ComponentAdministrationError::Unavailable);
        }
        Ok(Self {
            pool,
            checkpoint_key: SecretBytes::new(checkpoint_key),
            policy: PolicyStore::in_memory(None),
        })
    }

    /// Attach the deployment's hot, precompiled action-policy source.
    #[must_use]
    pub fn with_policy(mut self, policy: PolicyStore) -> Self {
        self.policy = policy;
        self
    }

    async fn retire_component_human_decision(
        &self,
        scope: &ComponentHumanDecisionScope,
        decision_id: &str,
        state: &'static str,
        event_type: &'static str,
    ) -> Result<(), ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT bot_id,component_name,arguments_hash
                   FROM public.component_human_decisions
                  WHERE decision_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND thread_id=$4
                    AND run_id=$5 AND actor_id=$6 AND bot_id=$7 AND state='pending'
                  FOR UPDATE",
                &[
                    &decision_id,
                    &scope.deployment.as_str(),
                    &scope.tenant.as_str(),
                    &scope.thread_id.as_str(),
                    &scope.run_id.as_str(),
                    &scope.actor.as_str(),
                    &scope.agent_id.as_str(),
                ],
            )
            .await
            .map_err(query_unavailable)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(query_unavailable)?;
            return Ok(());
        };
        let updated = transaction
            .execute(
                "UPDATE public.component_human_decisions
                    SET state=$2,answer=NULL,resolved_at=clock_timestamp(),resolved_by=NULL,
                        updated_at=clock_timestamp()
                  WHERE decision_id=$1 AND state='pending'",
                &[&decision_id, &state],
            )
            .await
            .map_err(query_unavailable)?;
        if updated == 1 {
            append_component_human_answer_audit(
                &transaction,
                &scope.actor,
                decision_id,
                row.try_get("bot_id").map_err(|_| corrupt("agent_id"))?,
                row.try_get("component_name")
                    .map_err(|_| corrupt("component_name"))?,
                row.try_get("arguments_hash")
                    .map_err(|_| corrupt("component_arguments_hash"))?,
                event_type,
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        commit_component_runtime(transaction, "component_human_retired").await
    }

    fn authorize_function(
        &self,
        scope: &ComponentRuntimeScope,
        function: &str,
    ) -> FunctionAuthorization {
        if !component_data_function_manifest()
            .iter()
            .any(|entry| entry.name == function)
        {
            return FunctionAuthorization::refused(ComponentDecisionRefusal::FunctionUnavailable {
                function: function.to_owned(),
            });
        }
        if !scope.admin {
            return FunctionAuthorization::refused(
                ComponentDecisionRefusal::FunctionActorNotAuthorized {
                    function: function.to_owned(),
                },
            );
        }
        let compiled = self.policy.compiled();
        let decision = evaluate(
            &compiled,
            &PolicyContext {
                tool: ToolRef {
                    name: format!("component_data__{function}"),
                },
                bot: BotRef {
                    id: scope.agent_id.as_str().to_owned(),
                },
                page: PageRef {
                    url: String::new(),
                    host: String::new(),
                },
                actor: ActorRef {
                    id: scope.actor.as_str().to_owned(),
                },
                element: None,
                key: None,
                intent: Some(Intent::ReadTool),
                file: None,
                mcp: None,
                command: None,
            },
        );
        let policy_version = decision.policy_version.to_hex();
        if !decision.forward {
            let refused_rule = decision.matched.map_or_else(
                || "policy.default_deny".to_owned(),
                |rule| format!("policy.rule.{}", Sha256Digest::of(rule.as_bytes()).to_hex()),
            );
            return FunctionAuthorization {
                refusal: Some(ComponentDecisionRefusal::FunctionPolicyRefused {
                    function: function.to_owned(),
                }),
                policy_version: Some(policy_version),
                refused_rule: Some(refused_rule),
            };
        }
        FunctionAuthorization {
            refusal: None,
            policy_version: Some(policy_version),
            refused_rule: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FunctionAuthorization {
    refusal: Option<ComponentDecisionRefusal>,
    policy_version: Option<String>,
    refused_rule: Option<String>,
}

impl FunctionAuthorization {
    fn refused(refusal: ComponentDecisionRefusal) -> Self {
        Self {
            refusal: Some(refusal),
            policy_version: None,
            refused_rule: None,
        }
    }
}

impl core::fmt::Debug for PostgresComponentAdministration {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PostgresComponentAdministration")
            .field("checkpoint_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ComponentAdministration for PostgresComponentAdministration {
    async fn list_components(
        &self,
        _auth: &AuthContext,
    ) -> Result<ComponentRecords, ComponentAdministrationError> {
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT c.name,c.title,c.kind,c.draft_description,c.published_description,
                        c.published,c.published_at,c.updated_by,c.updated_at,
                        coalesce((SELECT array_agg(e.agent_id ORDER BY e.agent_id)
                                    FROM public.component_exclusions e
                                   WHERE e.component_name=c.name),ARRAY[]::text[]) AS withheld_from,
                        coalesce((SELECT array_agg(f.function_name ORDER BY f.function_name)
                                    FROM public.component_functions f
                                   WHERE f.component_name=c.name),ARRAY[]::text[]) AS functions
                   FROM public.components c
                  ORDER BY c.kind,c.title,c.name",
                &[],
            )
            .await
            .map_err(query_unavailable)?;
        let components = rows
            .iter()
            .map(decode_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ComponentRecords { components })
    }

    async fn sync_catalogue(
        &self,
        auth: &AuthContext,
        entries: &[CompiledComponentManifestEntry],
    ) -> Result<ComponentCatalogueAdded, ComponentAdministrationError> {
        validate_manifest_entries(entries)?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(query_unavailable)?;
        let mut added = Vec::with_capacity(entries.len());
        for entry in entries {
            let inserted = transaction
                .query_opt(
                    "INSERT INTO public.components(
                       name,title,kind,draft_description,published_description,published,
                       published_at,updated_by,created_at,updated_at
                     ) VALUES($1,$2,$3,$4,$4,true,clock_timestamp(),'the build',
                              clock_timestamp(),clock_timestamp())
                     ON CONFLICT (name) DO NOTHING RETURNING name",
                    &[
                        &entry.name,
                        &entry.title,
                        &entry.kind.as_str(),
                        &entry.description,
                    ],
                )
                .await
                .map_err(query_unavailable)?;
            if inserted.is_none() {
                continue;
            }
            let target_id =
                AuditIdentifier::new(entry.name.clone()).map_err(|_| corrupt("component_name"))?;
            let (id, created_at) = next_event_coordinates(&transaction)
                .await
                .map_err(infra_unavailable)?;
            let event = AuditEvent {
                id,
                actor: Some(auth.actor().clone()),
                event_type: AuditEventType::parse("component.published")
                    .ok_or_else(|| corrupt("audit_event"))?,
                target_kind: AuditLabel::new("component"),
                target_id: Some(target_id),
                payload: AuditPayload::empty(),
                created_at,
            };
            append_event_in_transaction(&transaction, &event, self.checkpoint_key.expose())
                .await
                .map_err(infra_unavailable)?;
            added.push(entry.name.clone());
        }
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "component catalogue commit result unknown");
            ComponentAdministrationError::CommitUnknown
        })?;
        Ok(ComponentCatalogueAdded { added })
    }

    async fn update_component_governance(
        &self,
        auth: &AuthContext,
        mutation: &ComponentGovernanceMutation,
    ) -> Result<ComponentRecord, ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let component_name = mutation.component_name();
        let component = transaction
            .query_opt(
                "SELECT kind,draft_description FROM public.components
                  WHERE name=$1 FOR UPDATE",
                &[&component_name],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(ComponentAdministrationError::NotVisible)?;
        let kind = component
            .try_get::<_, String>("kind")
            .map_err(|_| corrupt("component_kind"))?;

        let (event_type, fact) = match mutation {
            ComponentGovernanceMutation::SetAgentGrant {
                agent_id, granted, ..
            } => {
                ensure_runnable_agent(
                    &transaction,
                    &ComponentRuntimeScope {
                        tenant: auth.tenant().clone(),
                        actor: auth.actor().clone(),
                        admin: auth.has_role(openbot_contracts::auth::Role::Admin),
                        agent_id: agent_id.clone(),
                    },
                )
                .await?;
                if *granted {
                    transaction
                        .execute(
                            "DELETE FROM public.component_exclusions
                              WHERE component_name=$1 AND agent_id=$2",
                            &[&component_name, &agent_id.as_str()],
                        )
                        .await
                        .map_err(query_unavailable)?;
                } else {
                    transaction
                        .execute(
                            "INSERT INTO public.component_exclusions(
                               component_name,agent_id,withheld_by,created_at,updated_at
                             ) VALUES($1,$2,$3,clock_timestamp(),clock_timestamp())
                             ON CONFLICT(component_name,agent_id) DO NOTHING",
                            &[&component_name, &agent_id.as_str(), &auth.actor().as_str()],
                        )
                        .await
                        .map_err(query_unavailable)?;
                }
                (
                    if *granted {
                        "component.granted"
                    } else {
                        "component.revoked"
                    },
                    Some(AuditFact::Bot(
                        AuditIdentifier::new(agent_id.as_str().to_owned())
                            .map_err(|_| corrupt("agent_id"))?,
                    )),
                )
            }
            ComponentGovernanceMutation::SetFunctionGrant {
                function, granted, ..
            } => {
                if kind == CompiledComponentKind::Sandboxed.as_str() {
                    return Err(ComponentAdministrationError::Conflict);
                }
                if !component_data_function_manifest()
                    .iter()
                    .any(|entry| entry.name == *function)
                {
                    return Err(ComponentAdministrationError::InvalidInput { field: "function" });
                }
                if *granted {
                    transaction
                        .execute(
                            "INSERT INTO public.component_functions(
                               component_name,function_name,granted_by,created_at,updated_at
                             ) VALUES($1,$2,$3,clock_timestamp(),clock_timestamp())
                             ON CONFLICT(component_name,function_name) DO NOTHING",
                            &[&component_name, function, &auth.actor().as_str()],
                        )
                        .await
                        .map_err(query_unavailable)?;
                } else {
                    transaction
                        .execute(
                            "DELETE FROM public.component_functions
                              WHERE component_name=$1 AND function_name=$2",
                            &[&component_name, function],
                        )
                        .await
                        .map_err(query_unavailable)?;
                }
                (
                    if *granted {
                        "component.function_granted"
                    } else {
                        "component.function_revoked"
                    },
                    Some(AuditFact::ComponentFunction(
                        AuditIdentifier::new(function.clone())
                            .map_err(|_| corrupt("component_function"))?,
                    )),
                )
            }
            ComponentGovernanceMutation::SetPublication { published, .. } => {
                if kind == CompiledComponentKind::Sandboxed.as_str() {
                    return Err(ComponentAdministrationError::Conflict);
                }
                if *published {
                    let draft = component
                        .try_get::<_, String>("draft_description")
                        .map_err(|_| corrupt("draft_description"))?;
                    validate_description(&draft, "draft_description")?;
                    transaction
                        .execute(
                            "UPDATE public.components
                                SET published_description=draft_description,published=true,
                                    published_at=clock_timestamp(),updated_by=$2,
                                    updated_at=clock_timestamp()
                              WHERE name=$1",
                            &[&component_name, &auth.actor().as_str()],
                        )
                        .await
                        .map_err(query_unavailable)?;
                } else {
                    transaction
                        .execute(
                            "UPDATE public.components
                                SET published=false,updated_by=$2,updated_at=clock_timestamp()
                              WHERE name=$1",
                            &[&component_name, &auth.actor().as_str()],
                        )
                        .await
                        .map_err(query_unavailable)?;
                }
                (
                    if *published {
                        "component.published"
                    } else {
                        "component.unpublished"
                    },
                    None,
                )
            }
            ComponentGovernanceMutation::SaveDraft { description, .. } => {
                if kind == CompiledComponentKind::Sandboxed.as_str() {
                    return Err(ComponentAdministrationError::Conflict);
                }
                validate_description(description, "description")?;
                transaction
                    .execute(
                        "UPDATE public.components
                            SET draft_description=$2,updated_by=$3,updated_at=clock_timestamp()
                          WHERE name=$1",
                        &[&component_name, description, &auth.actor().as_str()],
                    )
                    .await
                    .map_err(query_unavailable)?;
                ("component.draft_saved", None)
            }
        };

        append_component_governance_audit(
            &transaction,
            auth,
            component_name,
            event_type,
            fact,
            self.checkpoint_key.expose(),
        )
        .await?;
        let component = load_component_record(&transaction, component_name).await?;
        transaction.commit().await.map_err(|error| {
            tracing::error!(error = %error, "component governance commit result unknown");
            ComponentAdministrationError::CommitUnknown
        })?;
        Ok(component)
    }

    async fn list_components_for_agent(
        &self,
        scope: &ComponentRuntimeScope,
        renderer_names: &[String],
    ) -> Result<GrantedCompiledComponents, ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_runnable_agent(&transaction, scope).await?;
        let names = renderer_names.to_vec();
        let rows = transaction
            .query(
                "SELECT c.name,c.published_description AS description
                   FROM public.components c
              LEFT JOIN public.component_exclusions e
                     ON e.component_name=c.name AND e.agent_id=$1
                  WHERE c.name=ANY($2::text[])
                    AND c.published=true
                    AND c.published_description IS NOT NULL
                    AND e.agent_id IS NULL
               ORDER BY c.name",
                &[&scope.agent_id.as_str(), &names],
            )
            .await
            .map_err(query_unavailable)?;
        let components = rows
            .iter()
            .map(|row| {
                let name = row
                    .try_get::<_, String>("name")
                    .map_err(|_| corrupt("component_name"))?;
                let description = row
                    .try_get::<_, String>("description")
                    .map_err(|_| corrupt("published_description"))?;
                validate_name(&name)?;
                validate_description(&description, "published_description")?;
                Ok(GrantedCompiledComponent { name, description })
            })
            .collect::<Result<Vec<_>, ComponentAdministrationError>>()?;
        transaction.commit().await.map_err(query_unavailable)?;
        Ok(GrantedCompiledComponents { components })
    }

    async fn decide_component(
        &self,
        scope: &ComponentRuntimeScope,
        component_name: &str,
        build_has_renderer: bool,
        functions: &[String],
    ) -> Result<ComponentDecision, ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_runnable_agent(&transaction, scope).await?;
        let facts =
            component_grant_facts(&transaction, scope, component_name, build_has_renderer).await?;
        if let ComponentGrantDecision::Refused(reason) = decide_component_grant(facts) {
            let refusal = component_refusal(reason, None)?;
            append_component_refusal(
                &transaction,
                scope,
                component_name,
                &refusal,
                None,
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "component_refusal").await?;
            return Ok(ComponentDecision::refused(refusal));
        }

        if !functions.is_empty() {
            let requested = functions.to_vec();
            let rows = transaction
                .query(
                    "SELECT function_name
                       FROM public.component_functions
                      WHERE component_name=$1 AND function_name=ANY($2::text[])
                   ORDER BY function_name",
                    &[&component_name, &requested],
                )
                .await
                .map_err(query_unavailable)?;
            let granted = rows
                .iter()
                .map(|row| {
                    row.try_get::<_, String>("function_name")
                        .map_err(|_| corrupt("component_function"))
                })
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
            for function in functions {
                let authorization = self.authorize_function(scope, function);
                if let Some(refusal) = authorization.refusal.clone() {
                    append_component_refusal(
                        &transaction,
                        scope,
                        component_name,
                        &refusal,
                        Some(&authorization),
                        self.checkpoint_key.expose(),
                    )
                    .await?;
                    commit_component_runtime(transaction, "function_authorization_refusal").await?;
                    return Ok(ComponentDecision::refused(refusal));
                }
                if let ComponentGrantDecision::Refused(reason) =
                    decide_component_function_grant(granted.contains(function))
                {
                    let refusal = component_refusal(reason, Some(function.clone()))?;
                    append_component_refusal(
                        &transaction,
                        scope,
                        component_name,
                        &refusal,
                        Some(&authorization),
                        self.checkpoint_key.expose(),
                    )
                    .await?;
                    commit_component_runtime(transaction, "function_grant_refusal").await?;
                    return Ok(ComponentDecision::refused(refusal));
                }
            }
        }

        transaction.commit().await.map_err(query_unavailable)?;
        Ok(ComponentDecision::allowed())
    }

    async fn call_component_function(
        &self,
        scope: &ComponentRuntimeScope,
        component_name: &str,
        build_has_renderer: bool,
        plan: &ComponentFunctionCallPlan,
    ) -> Result<ComponentFunctionCall, ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_runnable_agent(&transaction, scope).await?;
        let component_facts =
            component_grant_facts(&transaction, scope, component_name, build_has_renderer).await?;
        if let ComponentGrantDecision::Refused(reason) = decide_component_grant(component_facts) {
            let refusal = component_refusal(reason, None)?;
            append_component_refusal(
                &transaction,
                scope,
                component_name,
                &refusal,
                None,
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "call_component_refusal").await?;
            return Ok(ComponentFunctionCall::refused(refusal));
        }

        let authorization = self.authorize_function(scope, &plan.function);
        if let Some(refusal) = authorization.refusal.clone() {
            append_component_refusal(
                &transaction,
                scope,
                component_name,
                &refusal,
                Some(&authorization),
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "call_function_authorization_refusal").await?;
            return Ok(ComponentFunctionCall::refused(refusal));
        }

        let granted = transaction
            .query_opt(
                "SELECT function_name
                   FROM public.component_functions
                  WHERE component_name=$1 AND function_name=$2",
                &[&component_name, &plan.function],
            )
            .await
            .map_err(query_unavailable)?
            .is_some();
        if let ComponentGrantDecision::Refused(reason) = decide_component_function_grant(granted) {
            let refusal = component_refusal(reason, Some(plan.function.clone()))?;
            append_component_refusal(
                &transaction,
                scope,
                component_name,
                &refusal,
                Some(&authorization),
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "call_function_grant_refusal").await?;
            return Ok(ComponentFunctionCall::refused(refusal));
        }

        let Some(arguments) = plan.arguments else {
            return Err(corrupt("component_function_arguments"));
        };
        transaction
            .batch_execute("SAVEPOINT component_function_read")
            .await
            .map_err(query_unavailable)?;
        match execute_component_function(&transaction, &plan.function, arguments).await {
            Ok(data) => {
                transaction
                    .batch_execute("RELEASE SAVEPOINT component_function_read")
                    .await
                    .map_err(query_unavailable)?;
                append_component_function_outcome(
                    &transaction,
                    scope,
                    component_name,
                    &plan.function,
                    &authorization,
                    "component.function_called",
                    None,
                    self.checkpoint_key.expose(),
                )
                .await?;
                commit_component_runtime(transaction, "component_function_called").await?;
                Ok(ComponentFunctionCall::succeeded(data))
            }
            Err(error) => {
                tracing::warn!(error = %error, "component data function read failed");
                transaction
                    .batch_execute(
                        "ROLLBACK TO SAVEPOINT component_function_read; \
                         RELEASE SAVEPOINT component_function_read",
                    )
                    .await
                    .map_err(query_unavailable)?;
                append_component_function_outcome(
                    &transaction,
                    scope,
                    component_name,
                    &plan.function,
                    &authorization,
                    "component.function_failed",
                    Some("component_function_read_failed"),
                    self.checkpoint_key.expose(),
                )
                .await?;
                commit_component_runtime(transaction, "component_function_failed").await?;
                Ok(ComponentFunctionCall::failed(
                    ComponentFunctionError::ReadFailed,
                ))
            }
        }
    }

    async fn request_component_human_decision(
        &self,
        scope: &ComponentHumanDecisionScope,
        draft: &ComponentHumanDecisionDraft,
    ) -> Result<PendingComponentHumanDecision, ComponentAdministrationError> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        ensure_component_human_scope(&transaction, scope).await?;
        let runtime_scope = component_runtime_scope(scope);
        ensure_runnable_agent(&transaction, &runtime_scope).await?;
        let facts =
            component_grant_facts(&transaction, &runtime_scope, &draft.component_name, true)
                .await?;
        if let ComponentGrantDecision::Refused(reason) = decide_component_grant(facts) {
            let refusal = component_refusal(reason, None)?;
            append_component_refusal(
                &transaction,
                &runtime_scope,
                &draft.component_name,
                &refusal,
                None,
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "component_human_refused").await?;
            return Err(ComponentAdministrationError::NotVisible);
        }
        crate::thread_history_writer::require_open(&transaction, &scope.thread_id)
            .await
            .map_err(component_writer_error)?;
        ensure_component_human_scope(&transaction, scope).await?;
        ensure_runnable_agent(&transaction, &runtime_scope).await?;
        let ttl_seconds = i64::try_from(draft.ttl.as_secs())
            .map_err(|_| corrupt("component_human_decision_ttl"))?;
        let generation =
            i64::try_from(scope.auth_generation.get()).map_err(|_| corrupt("auth_generation"))?;
        let arguments_hash = draft.arguments_hash.to_hex();
        let inserted = transaction
            .query_opt(
                "INSERT INTO public.component_human_decisions(
                   decision_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,
                   auth_generation,provider_call_id,component_name,arguments,arguments_hash,
                   state,answer,requested_at,expires_at,resolved_at,resolved_by,created_at,updated_at
                 ) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NULL,
                          clock.now,clock.now+make_interval(secs=>$13::bigint),NULL,NULL,clock.now,clock.now
                     FROM (SELECT clock_timestamp() AS now) clock
                 ON CONFLICT (run_id,provider_call_id) DO NOTHING
                 RETURNING decision_id,run_id,provider_call_id,bot_id,component_name,arguments,
                           requested_at,expires_at",
                &[
                    &draft.decision_id,
                    &scope.deployment.as_str(),
                    &scope.tenant.as_str(),
                    &scope.thread_id.as_str(),
                    &scope.run_id.as_str(),
                    &scope.actor.as_str(),
                    &scope.agent_id.as_str(),
                    &generation,
                    &draft.provider_call_id,
                    &draft.component_name,
                    &draft.arguments,
                    &arguments_hash,
                    &ttl_seconds,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        let (pending, created) = if let Some(row) = inserted {
            (decode_pending_human_decision(&row)?, true)
        } else {
            let row = transaction
                .query_opt(
                    "SELECT decision_id,run_id,bot_id,component_name,arguments,arguments_hash,
                            provider_call_id,actor_id,auth_generation,state,requested_at,expires_at
                       FROM public.component_human_decisions
                      WHERE run_id=$1 AND provider_call_id=$2 FOR UPDATE",
                    &[&scope.run_id.as_str(), &draft.provider_call_id],
                )
                .await
                .map_err(query_unavailable)?
                .ok_or_else(|| corrupt("component_human_decision"))?;
            let state: String = row
                .try_get("state")
                .map_err(|_| corrupt("decision_state"))?;
            let exact = row
                .try_get::<_, String>("decision_id")
                .is_ok_and(|value| value == draft.decision_id)
                && row
                    .try_get::<_, String>("actor_id")
                    .is_ok_and(|value| value == scope.actor.as_str())
                && row
                    .try_get::<_, String>("bot_id")
                    .is_ok_and(|value| value == scope.agent_id.as_str())
                && row
                    .try_get::<_, i64>("auth_generation")
                    .is_ok_and(|value| value == generation)
                && row
                    .try_get::<_, String>("component_name")
                    .is_ok_and(|value| value == draft.component_name)
                && row
                    .try_get::<_, serde_json::Value>("arguments")
                    .is_ok_and(|value| value == draft.arguments)
                && row
                    .try_get::<_, String>("arguments_hash")
                    .is_ok_and(|value| value == arguments_hash)
                && state == "pending";
            if !exact {
                return Err(ComponentAdministrationError::Conflict);
            }
            (decode_pending_human_decision(&row)?, false)
        };
        if created {
            append_component_human_audit(
                &transaction,
                scope,
                draft,
                "component.human_requested",
                self.checkpoint_key.expose(),
            )
            .await?;
        }
        commit_component_runtime(transaction, "component_human_requested").await?;
        Ok(pending)
    }

    async fn list_component_human_decisions(
        &self,
        auth: &AuthContext,
    ) -> Result<PendingComponentHumanDecisions, ComponentAdministrationError> {
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let client = self.pool.get().await.map_err(unavailable)?;
        let rows = client
            .query(
                "SELECT d.decision_id,d.run_id,d.provider_call_id,d.bot_id,d.component_name,d.arguments,
                        d.requested_at,d.expires_at
                   FROM public.component_human_decisions d
                   JOIN public.runs r ON r.run_id=d.run_id AND r.thread_id=d.thread_id
                   JOIN public.threads t ON t.thread_id=d.thread_id
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id
                   JOIN public.users u ON u.id=d.actor_id
                  WHERE d.actor_id=$1 AND d.deployment_id=$2 AND d.tenant_id=$3
                    AND d.auth_generation=$4 AND d.state='pending'
                    AND d.expires_at>clock_timestamp() AND r.actor_id=$1 AND r.bot_id=d.bot_id
                    AND r.status='running' AND t.status<>'deleted'
                    AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp()
                    AND coalesce(u.auth_generation,0)=$4
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                    WHERE ra.email=lower(u.email))
                    AND ((t.anchor_kind='direct_bot' AND EXISTS(
                           SELECT 1 FROM public.thread_memberships tm
                            WHERE tm.thread_id=t.thread_id AND tm.user_id=$1
                         )) OR (t.anchor_kind='channel' AND EXISTS(
                           SELECT 1 FROM public.channel_memberships cm
                            WHERE cm.channel_id=t.anchor_id AND cm.user_id=$1
                         )))
                  ORDER BY d.requested_at,d.decision_id LIMIT 100",
                &[
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(query_unavailable)?;
        let decisions = rows
            .iter()
            .map(decode_pending_human_decision)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PendingComponentHumanDecisions { decisions })
    }

    async fn resolve_component_human_decision(
        &self,
        auth: &AuthContext,
        decision_id: &str,
        answer: &ComponentHumanDecisionAnswer,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        let generation =
            i64::try_from(auth.auth_generation().get()).map_err(|_| corrupt("auth_generation"))?;
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .await
            .map_err(query_unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT d.decision_id,d.run_id,d.thread_id,d.bot_id,d.component_name,d.arguments,
                        d.arguments_hash,d.state,d.answer,d.expires_at,clock_timestamp() AS now
                   FROM public.component_human_decisions d
                   JOIN public.runs r ON r.run_id=d.run_id AND r.thread_id=d.thread_id
                   JOIN public.threads t ON t.thread_id=d.thread_id
                   JOIN public.thread_leases l ON l.thread_id=t.thread_id
                   JOIN public.users u ON u.id=d.actor_id
                  WHERE d.decision_id=$1 AND d.actor_id=$2 AND d.deployment_id=$3
                    AND d.tenant_id=$4 AND d.auth_generation=$5
                    AND r.actor_id=$2 AND r.bot_id=d.bot_id AND r.status='running'
                    AND t.status<>'deleted' AND l.fencing_token=r.fencing_token
                    AND l.expires_at>clock_timestamp() AND coalesce(u.auth_generation,0)=$5
                    AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                    AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                    WHERE ra.email=lower(u.email))
                    AND ((t.anchor_kind='direct_bot' AND EXISTS(
                           SELECT 1 FROM public.thread_memberships tm
                            WHERE tm.thread_id=t.thread_id AND tm.user_id=$2
                         )) OR (t.anchor_kind='channel' AND EXISTS(
                           SELECT 1 FROM public.channel_memberships cm
                            WHERE cm.channel_id=t.anchor_id AND cm.user_id=$2
                         )))
                  FOR UPDATE OF d",
                &[
                    &decision_id,
                    &auth.actor().as_str(),
                    &auth.deployment().as_str(),
                    &auth.tenant().as_str(),
                    &generation,
                ],
            )
            .await
            .map_err(query_unavailable)?
            .ok_or(ComponentAdministrationError::NotVisible)?;
        let state: String = row
            .try_get("state")
            .map_err(|_| corrupt("decision_state"))?;
        if state == "answered" {
            let stored = decode_human_answer(
                row.try_get("answer")
                    .map_err(|_| corrupt("decision_answer"))?,
            )?;
            if &stored != answer {
                return Err(ComponentAdministrationError::Conflict);
            }
            transaction.commit().await.map_err(query_unavailable)?;
            return Ok(ComponentHumanDecisionResolved {
                decision_id: decision_id.to_owned(),
                answer: stored,
                replayed: true,
            });
        }
        if state != "pending" {
            return Err(ComponentAdministrationError::NotVisible);
        }
        let expires_at: time::OffsetDateTime = row
            .try_get("expires_at")
            .map_err(|_| corrupt("expires_at"))?;
        let now: time::OffsetDateTime = row.try_get("now").map_err(|_| corrupt("clock"))?;
        if expires_at <= now {
            expire_component_human_decision(
                &transaction,
                auth.actor(),
                decision_id,
                row.try_get::<_, String>("bot_id")
                    .map_err(|_| corrupt("agent_id"))?,
                row.try_get::<_, String>("component_name")
                    .map_err(|_| corrupt("component_name"))?,
                row.try_get::<_, String>("arguments_hash")
                    .map_err(|_| corrupt("component_arguments_hash"))?,
                self.checkpoint_key.expose(),
            )
            .await?;
            commit_component_runtime(transaction, "component_human_expired").await?;
            return Err(ComponentAdministrationError::NotVisible);
        }
        let actual_thread: String = row.try_get("thread_id").map_err(|_| corrupt("thread_id"))?;
        crate::thread_history_writer::require_open(
            &transaction,
            &openbot_contracts::ids::ThreadId::new(actual_thread),
        )
        .await
        .map_err(component_writer_error)?;
        let component_name: String = row
            .try_get("component_name")
            .map_err(|_| corrupt("component_name"))?;
        let arguments: serde_json::Value = row
            .try_get("arguments")
            .map_err(|_| corrupt("component_arguments"))?;
        validate_human_answer_against_arguments(&component_name, &arguments, answer)?;
        let answer_json = serde_json::to_value(answer).map_err(|_| corrupt("decision_answer"))?;
        let updated = transaction
            .execute(
                "UPDATE public.component_human_decisions
                    SET state='answered',answer=$2,resolved_at=clock_timestamp(),resolved_by=actor_id,
                        updated_at=clock_timestamp()
                  WHERE decision_id=$1 AND state='pending'",
                &[&decision_id, &answer_json],
            )
            .await
            .map_err(query_unavailable)?;
        if updated != 1 {
            return Err(ComponentAdministrationError::Conflict);
        }
        append_component_human_answer_audit(
            &transaction,
            auth.actor(),
            decision_id,
            row.try_get::<_, String>("bot_id")
                .map_err(|_| corrupt("agent_id"))?,
            component_name,
            row.try_get::<_, String>("arguments_hash")
                .map_err(|_| corrupt("component_arguments_hash"))?,
            "component.human_answered",
            self.checkpoint_key.expose(),
        )
        .await?;
        commit_component_runtime(transaction, "component_human_answered").await?;
        Ok(ComponentHumanDecisionResolved {
            decision_id: decision_id.to_owned(),
            answer: answer.clone(),
            replayed: false,
        })
    }

    async fn wait_component_human_decision(
        &self,
        scope: &ComponentHumanDecisionScope,
        decision_id: &str,
    ) -> Result<ComponentHumanDecisionResolved, ComponentAdministrationError> {
        loop {
            let client = self.pool.get().await.map_err(unavailable)?;
            let row = client
                .query_opt(
                    "SELECT state,answer,expires_at,clock_timestamp() AS now,
                            EXISTS(
                              SELECT 1 FROM public.runs r
                              JOIN public.threads t ON t.thread_id=r.thread_id
                              JOIN public.thread_leases l ON l.thread_id=t.thread_id
                              JOIN public.users u ON u.id=r.actor_id
                              WHERE r.run_id=d.run_id AND r.thread_id=d.thread_id
                                AND r.bot_id=d.bot_id AND r.actor_id=d.actor_id
                                AND r.status='running' AND t.deployment_id=d.deployment_id
                                AND t.tenant_id=d.tenant_id AND t.status<>'deleted'
                                AND l.fencing_token=r.fencing_token
                                AND l.expires_at>clock_timestamp()
                                AND coalesce(u.auth_generation,0)=d.auth_generation
                                AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                                AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                                WHERE ra.email=lower(u.email))
                                AND ((t.anchor_kind='direct_bot' AND EXISTS(
                                       SELECT 1 FROM public.thread_memberships tm
                                        WHERE tm.thread_id=t.thread_id AND tm.user_id=d.actor_id
                                     )) OR (t.anchor_kind='channel' AND EXISTS(
                                       SELECT 1 FROM public.channel_memberships cm
                                        WHERE cm.channel_id=t.anchor_id AND cm.user_id=d.actor_id
                                     )))
                            ) AS scope_current
                       FROM public.component_human_decisions d
                      WHERE decision_id=$1 AND run_id=$2 AND actor_id=$3 AND bot_id=$4
                        AND deployment_id=$5 AND tenant_id=$6 AND thread_id=$7
                        AND auth_generation=$8",
                    &[
                        &decision_id,
                        &scope.run_id.as_str(),
                        &scope.actor.as_str(),
                        &scope.agent_id.as_str(),
                        &scope.deployment.as_str(),
                        &scope.tenant.as_str(),
                        &scope.thread_id.as_str(),
                        &i64::try_from(scope.auth_generation.get())
                            .map_err(|_| corrupt("auth_generation"))?,
                    ],
                )
                .await
                .map_err(query_unavailable)?
                .ok_or(ComponentAdministrationError::NotVisible)?;
            let state: String = row
                .try_get("state")
                .map_err(|_| corrupt("decision_state"))?;
            if state == "answered" {
                return Ok(ComponentHumanDecisionResolved {
                    decision_id: decision_id.to_owned(),
                    answer: decode_human_answer(
                        row.try_get("answer")
                            .map_err(|_| corrupt("decision_answer"))?,
                    )?,
                    replayed: false,
                });
            }
            let current: bool = row
                .try_get("scope_current")
                .map_err(|_| corrupt("decision_scope"))?;
            let expires_at: time::OffsetDateTime = row
                .try_get("expires_at")
                .map_err(|_| corrupt("expires_at"))?;
            let now: time::OffsetDateTime = row.try_get("now").map_err(|_| corrupt("clock"))?;
            if state != "pending" {
                return Err(ComponentAdministrationError::NotVisible);
            }
            if !current {
                drop(client);
                self.retire_component_human_decision(
                    scope,
                    decision_id,
                    "cancelled",
                    "component.human_cancelled",
                )
                .await?;
                return Err(ComponentAdministrationError::NotVisible);
            }
            if expires_at <= now {
                drop(client);
                self.retire_component_human_decision(
                    scope,
                    decision_id,
                    "expired",
                    "component.human_expired",
                )
                .await?;
                return Err(ComponentAdministrationError::NotVisible);
            }
            drop(client);
            tokio::time::sleep(HUMAN_DECISION_POLL_INTERVAL).await;
        }
    }
}

fn component_runtime_scope(scope: &ComponentHumanDecisionScope) -> ComponentRuntimeScope {
    ComponentRuntimeScope {
        tenant: scope.tenant.clone(),
        actor: scope.actor.clone(),
        admin: scope.admin,
        agent_id: scope.agent_id.clone(),
    }
}

async fn ensure_component_human_scope(
    transaction: &Transaction<'_>,
    scope: &ComponentHumanDecisionScope,
) -> Result<(), ComponentAdministrationError> {
    let generation =
        i64::try_from(scope.auth_generation.get()).map_err(|_| corrupt("auth_generation"))?;
    let current: bool = transaction
        .query_one(
            "SELECT EXISTS(
                SELECT 1 FROM public.runs r
                JOIN public.threads t ON t.thread_id=r.thread_id
                JOIN public.thread_leases l ON l.thread_id=t.thread_id
                JOIN public.users u ON u.id=r.actor_id
                WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4
                  AND r.status='running' AND t.deployment_id=$5 AND t.tenant_id=$6
                  AND t.status<>'deleted' AND l.fencing_token=r.fencing_token
                  AND l.expires_at>clock_timestamp() AND coalesce(u.auth_generation,0)=$7
                  AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id)
                  AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra
                                  WHERE ra.email=lower(u.email))
                  AND ((t.anchor_kind='direct_bot' AND EXISTS(
                         SELECT 1 FROM public.thread_memberships tm
                          WHERE tm.thread_id=t.thread_id AND tm.user_id=$4
                       )) OR (t.anchor_kind='channel' AND EXISTS(
                         SELECT 1 FROM public.channel_memberships cm
                          WHERE cm.channel_id=t.anchor_id AND cm.user_id=$4
                       )))
            )",
            &[
                &scope.run_id.as_str(),
                &scope.thread_id.as_str(),
                &scope.agent_id.as_str(),
                &scope.actor.as_str(),
                &scope.deployment.as_str(),
                &scope.tenant.as_str(),
                &generation,
            ],
        )
        .await
        .map_err(query_unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("component_human_scope"))?;
    if current {
        Ok(())
    } else {
        Err(ComponentAdministrationError::NotVisible)
    }
}

async fn component_grant_facts(
    transaction: &Transaction<'_>,
    scope: &ComponentRuntimeScope,
    component_name: &str,
    build_has_renderer: bool,
) -> Result<ComponentGrantFacts, ComponentAdministrationError> {
    let row = transaction
        .query_one(
            "SELECT (c.name IS NOT NULL) AS component_exists,
                    coalesce(c.published,false) AS published,
                    (c.published_description IS NOT NULL) AS has_published_description,
                    (e.agent_id IS NOT NULL) AS withheld_from_agent
               FROM (VALUES(1)) AS singleton(value)
          LEFT JOIN public.components c ON c.name=$1
          LEFT JOIN public.component_exclusions e
                 ON e.component_name=c.name AND e.agent_id=$2",
            &[&component_name, &scope.agent_id.as_str()],
        )
        .await
        .map_err(query_unavailable)?;
    Ok(ComponentGrantFacts {
        exists: build_has_renderer
            && row
                .try_get::<_, bool>("component_exists")
                .map_err(|_| corrupt("component_exists"))?,
        published: row.try_get("published").map_err(|_| corrupt("published"))?,
        has_published_description: row
            .try_get("has_published_description")
            .map_err(|_| corrupt("published_description"))?,
        withheld_from_agent: row
            .try_get("withheld_from_agent")
            .map_err(|_| corrupt("component_exclusion"))?,
    })
}

pub(crate) async fn ensure_runnable_agent(
    transaction: &Transaction<'_>,
    scope: &ComponentRuntimeScope,
) -> Result<(), ComponentAdministrationError> {
    let row = transaction
        .query_opt(
            "SELECT p.owner_user_id,p.visibility::text,
                    (a.package_id IS NOT NULL) AS system_owned,
                    (p.deleted_at IS NOT NULL) AS deleted,
                    (a.package_id IS NULL OR dp.tenant_id=$2) AS tenant_visible
               FROM public.agents a
               JOIN public.agent_profiles p ON p.agent_id=a.id
          LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
              WHERE a.id=$1",
            &[&scope.agent_id.as_str(), &scope.tenant.as_str()],
        )
        .await
        .map_err(query_unavailable)?
        .ok_or(ComponentAdministrationError::NotVisible)?;
    let tenant_visible: bool = row
        .try_get("tenant_visible")
        .map_err(|_| corrupt("agent_tenant"))?;
    if !tenant_visible {
        return Err(ComponentAdministrationError::NotVisible);
    }
    let visibility = match row
        .try_get::<_, String>("visibility")
        .map_err(|_| corrupt("agent_visibility"))?
        .as_str()
    {
        "public" => AgentVisibility::Public,
        "private" => AgentVisibility::Private,
        _ => return Err(corrupt("agent_visibility")),
    };
    let owner_user_id = row
        .try_get::<_, Option<String>>("owner_user_id")
        .map_err(|_| corrupt("agent_owner"))?;
    let actor = AgentActor {
        id: scope.actor.as_str(),
        admin: scope.admin,
    };
    let facts = AgentProfileFacts {
        owner_user_id: owner_user_id.as_deref(),
        visibility,
        system_owned: row
            .try_get("system_owned")
            .map_err(|_| corrupt("agent_system_owned"))?,
        deleted: row
            .try_get("deleted")
            .map_err(|_| corrupt("agent_deleted"))?,
    };
    if !can_run_agent(&actor, &facts) {
        return Err(ComponentAdministrationError::NotVisible);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum FunctionReadError {
    #[error("component_function_query_failed")]
    Query,
    #[error("component_function_data_corrupt field={0}")]
    Corrupt(&'static str),
}

async fn execute_component_function(
    transaction: &Transaction<'_>,
    function: &str,
    arguments: ComponentFunctionArguments,
) -> Result<ComponentFunctionData, FunctionReadError> {
    match (function, arguments) {
        (BOT_ACTIVITY_FUNCTION_NAME, ComponentFunctionArguments::BotActivity { days }) => {
            let days_i32 = i32::from(days);
            let rows = transaction
                .query(
                    "SELECT payload->>'bot' AS bot,count(*)::bigint AS actions
                       FROM public.audit_events
                      WHERE payload->>'bot' IS NOT NULL
                        AND created_at > clock_timestamp() - make_interval(days => $1)
                   GROUP BY 1
                   ORDER BY actions DESC,bot
                      LIMIT 12",
                    &[&days_i32],
                )
                .await
                .map_err(|_| FunctionReadError::Query)?;
            let rows = rows
                .iter()
                .map(|row| {
                    let bot = row
                        .try_get::<_, String>("bot")
                        .map_err(|_| FunctionReadError::Corrupt("bot"))?;
                    validate_function_value(&bot, 256, "bot")?;
                    let actions = row
                        .try_get::<_, i64>("actions")
                        .map_err(|_| FunctionReadError::Corrupt("actions"))?;
                    Ok(BotActivityRow {
                        bot,
                        actions: u64::try_from(actions)
                            .map_err(|_| FunctionReadError::Corrupt("actions"))?,
                    })
                })
                .collect::<Result<Vec<_>, FunctionReadError>>()?;
            Ok(ComponentFunctionData::BotActivity(BotActivityReport {
                days,
                rows,
            }))
        }
        (RECENT_REFUSALS_FUNCTION_NAME, ComponentFunctionArguments::RecentRefusals { limit }) => {
            let limit_i64 = i64::from(limit);
            let rows = transaction
                .query(
                    "SELECT created_at AS at,payload->>'bot' AS bot,event_type AS what,
                            coalesce(payload->>'error_code',payload->>'refused_by_rule',
                                     payload->>'reason') AS reason
                       FROM public.audit_events
                      WHERE event_type IN (
                            'computer.action_refused','component.refused',
                            'component.function_refused','bot.declined')
                   ORDER BY created_at DESC,id DESC
                      LIMIT $1",
                    &[&limit_i64],
                )
                .await
                .map_err(|_| FunctionReadError::Query)?;
            let rows = rows
                .iter()
                .map(|row| {
                    let bot = row
                        .try_get::<_, Option<String>>("bot")
                        .map_err(|_| FunctionReadError::Corrupt("bot"))?;
                    if let Some(bot) = bot.as_deref() {
                        validate_function_value(bot, 256, "bot")?;
                    }
                    let what = row
                        .try_get::<_, String>("what")
                        .map_err(|_| FunctionReadError::Corrupt("event_type"))?;
                    if AuditEventType::parse(&what).is_none() {
                        return Err(FunctionReadError::Corrupt("event_type"));
                    }
                    let reason = row
                        .try_get::<_, Option<String>>("reason")
                        .map_err(|_| FunctionReadError::Corrupt("reason"))?;
                    if let Some(reason) = reason.as_deref() {
                        validate_function_value(reason, 256, "reason")?;
                    }
                    Ok(RecentRefusalRow {
                        at: row
                            .try_get("at")
                            .map_err(|_| FunctionReadError::Corrupt("created_at"))?,
                        bot,
                        what,
                        reason,
                    })
                })
                .collect::<Result<Vec<_>, FunctionReadError>>()?;
            Ok(ComponentFunctionData::RecentRefusals(
                RecentRefusalsReport { rows },
            ))
        }
        _ => Err(FunctionReadError::Corrupt("arguments")),
    }
}

fn validate_function_value(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), FunctionReadError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(FunctionReadError::Corrupt(field))
    } else {
        Ok(())
    }
}

async fn load_component_record(
    transaction: &Transaction<'_>,
    component_name: &str,
) -> Result<ComponentRecord, ComponentAdministrationError> {
    let row = transaction
        .query_one(
            "SELECT c.name,c.title,c.kind,c.draft_description,c.published_description,
                    c.published,c.published_at,c.updated_by,c.updated_at,
                    coalesce((SELECT array_agg(e.agent_id ORDER BY e.agent_id)
                                FROM public.component_exclusions e
                               WHERE e.component_name=c.name),ARRAY[]::text[]) AS withheld_from,
                    coalesce((SELECT array_agg(f.function_name ORDER BY f.function_name)
                                FROM public.component_functions f
                               WHERE f.component_name=c.name),ARRAY[]::text[]) AS functions
               FROM public.components c WHERE c.name=$1",
            &[&component_name],
        )
        .await
        .map_err(query_unavailable)?;
    decode_record(&row)
}

async fn append_component_governance_audit(
    transaction: &Transaction<'_>,
    auth: &AuthContext,
    component_name: &str,
    event_type: &'static str,
    fact: Option<AuditFact>,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let payload = AuditPayload::from_facts(fact).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(auth.actor().clone()),
        event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("component"),
        target_id: Some(
            AuditIdentifier::new(component_name.to_owned())
                .map_err(|_| corrupt("component_name"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(infra_unavailable)
}

#[allow(clippy::too_many_arguments)]
async fn append_component_function_outcome(
    transaction: &Transaction<'_>,
    scope: &ComponentRuntimeScope,
    component_name: &str,
    function: &str,
    authorization: &FunctionAuthorization,
    event_type: &'static str,
    error_code: Option<&'static str>,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let policy_version = authorization
        .policy_version
        .as_ref()
        .ok_or_else(|| corrupt("policy_version"))?;
    let mut facts = vec![
        AuditFact::Bot(
            AuditIdentifier::new(scope.agent_id.as_str().to_owned())
                .map_err(|_| corrupt("agent_id"))?,
        ),
        AuditFact::ComponentFunction(
            AuditIdentifier::new(function.to_owned()).map_err(|_| corrupt("component_function"))?,
        ),
        AuditFact::ComponentReads(AuditLabel::new(AUDIT_TRAIL_READS_DESCRIPTION)),
        AuditFact::PolicyVersion(
            AuditIdentifier::new(policy_version.clone()).map_err(|_| corrupt("policy_version"))?,
        ),
    ];
    if let Some(error_code) = error_code {
        facts.push(AuditFact::ErrorCode(AuditLabel::new(error_code)));
    }
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(scope.actor.clone()),
        event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("component"),
        target_id: Some(
            AuditIdentifier::new(component_name.to_owned())
                .map_err(|_| corrupt("component_name"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map_err(infra_unavailable)?;
    Ok(())
}

pub(crate) fn component_refusal(
    reason: ComponentGrantRefusal,
    function: Option<String>,
) -> Result<ComponentDecisionRefusal, ComponentAdministrationError> {
    match reason {
        ComponentGrantRefusal::UnknownComponent => Ok(ComponentDecisionRefusal::UnknownComponent),
        ComponentGrantRefusal::Unpublished => Ok(ComponentDecisionRefusal::Unpublished),
        ComponentGrantRefusal::WithheldFromAgent => Ok(ComponentDecisionRefusal::WithheldFromAgent),
        ComponentGrantRefusal::FunctionNotGranted => function
            .map(|function| ComponentDecisionRefusal::FunctionNotGranted { function })
            .ok_or_else(|| corrupt("component_function")),
    }
}

async fn append_component_refusal(
    transaction: &Transaction<'_>,
    scope: &ComponentRuntimeScope,
    component_name: &str,
    refusal: &ComponentDecisionRefusal,
    authorization: Option<&FunctionAuthorization>,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let mut facts = vec![
        AuditFact::Bot(
            AuditIdentifier::new(scope.agent_id.as_str().to_owned())
                .map_err(|_| corrupt("agent_id"))?,
        ),
        AuditFact::ErrorCode(AuditLabel::new(refusal.code_str())),
    ];
    let event_type = if let Some(function) = refusal.function() {
        facts.push(AuditFact::ComponentFunction(
            AuditIdentifier::new(function.to_owned()).map_err(|_| corrupt("component_function"))?,
        ));
        if let Some(policy_version) = authorization.and_then(|value| value.policy_version.as_ref())
        {
            facts.push(AuditFact::PolicyVersion(
                AuditIdentifier::new(policy_version.clone())
                    .map_err(|_| corrupt("policy_version"))?,
            ));
        }
        if let Some(refused_rule) = authorization.and_then(|value| value.refused_rule.as_ref()) {
            facts.push(AuditFact::RefusedByRule(
                AuditIdentifier::new(refused_rule.clone()).map_err(|_| corrupt("policy_rule"))?,
            ));
        }
        "component.function_refused"
    } else {
        "component.refused"
    };
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(scope.actor.clone()),
        event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("component"),
        target_id: Some(
            AuditIdentifier::new(component_name.to_owned())
                .map_err(|_| corrupt("component_name"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map_err(infra_unavailable)?;
    Ok(())
}

pub(crate) async fn append_sandboxed_component_refusal(
    transaction: &Transaction<'_>,
    scope: &ComponentRuntimeScope,
    component_name: &str,
    refusal: &ComponentDecisionRefusal,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    append_component_refusal(
        transaction,
        scope,
        component_name,
        refusal,
        None,
        checkpoint_key,
    )
    .await
}

async fn append_component_human_audit(
    transaction: &Transaction<'_>,
    scope: &ComponentHumanDecisionScope,
    draft: &ComponentHumanDecisionDraft,
    event_type: &'static str,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let input_bytes = u64::try_from(draft.arguments.to_string().len())
        .map_err(|_| corrupt("component_arguments"))?;
    let facts = vec![
        AuditFact::Bot(
            AuditIdentifier::new(scope.agent_id.as_str().to_owned())
                .map_err(|_| corrupt("agent_id"))?,
        ),
        AuditFact::DecisionId(
            AuditIdentifier::new(draft.decision_id.clone()).map_err(|_| corrupt("decision_id"))?,
        ),
        AuditFact::ToolName(
            AuditIdentifier::new(draft.component_name.clone())
                .map_err(|_| corrupt("component_name"))?,
        ),
        AuditFact::CanonicalArgsHash(draft.arguments_hash),
        AuditFact::InputBytes(input_bytes),
    ];
    append_component_human_event(
        transaction,
        scope.actor.clone(),
        &draft.component_name,
        facts,
        event_type,
        checkpoint_key,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn append_component_human_answer_audit(
    transaction: &Transaction<'_>,
    actor: &openbot_contracts::ids::ActorId,
    decision_id: &str,
    bot_id: String,
    component_name: String,
    arguments_hash: String,
    event_type: &'static str,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let facts = vec![
        AuditFact::Bot(AuditIdentifier::new(bot_id).map_err(|_| corrupt("agent_id"))?),
        AuditFact::DecisionId(
            AuditIdentifier::new(decision_id.to_owned()).map_err(|_| corrupt("decision_id"))?,
        ),
        AuditFact::ToolName(
            AuditIdentifier::new(component_name.clone()).map_err(|_| corrupt("component_name"))?,
        ),
        AuditFact::CanonicalArgsHash(
            Sha256Digest::parse_hex(&arguments_hash)
                .map_err(|_| corrupt("component_arguments_hash"))?,
        ),
    ];
    append_component_human_event(
        transaction,
        actor.clone(),
        &component_name,
        facts,
        event_type,
        checkpoint_key,
    )
    .await
}

async fn append_component_human_event(
    transaction: &Transaction<'_>,
    actor: openbot_contracts::ids::ActorId,
    component_name: &str,
    facts: Vec<AuditFact>,
    event_type: &'static str,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let payload = AuditPayload::from_facts(facts).map_err(|_| corrupt("audit_payload"))?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(infra_unavailable)?;
    let event = AuditEvent {
        id,
        actor: Some(actor),
        event_type: AuditEventType::parse(event_type).ok_or_else(|| corrupt("audit_event"))?,
        target_kind: AuditLabel::new("component"),
        target_id: Some(
            AuditIdentifier::new(component_name.to_owned())
                .map_err(|_| corrupt("component_name"))?,
        ),
        payload,
        created_at,
    };
    append_event_in_transaction(transaction, &event, checkpoint_key)
        .await
        .map(|_| ())
        .map_err(infra_unavailable)
}

async fn expire_component_human_decision(
    transaction: &Transaction<'_>,
    actor: &openbot_contracts::ids::ActorId,
    decision_id: &str,
    bot_id: String,
    component_name: String,
    arguments_hash: String,
    checkpoint_key: &[u8],
) -> Result<(), ComponentAdministrationError> {
    let updated = transaction
        .execute(
            "UPDATE public.component_human_decisions
                SET state='expired',answer=NULL,resolved_at=clock_timestamp(),resolved_by=NULL,
                    updated_at=clock_timestamp()
              WHERE decision_id=$1 AND state='pending'",
            &[&decision_id],
        )
        .await
        .map_err(query_unavailable)?;
    if updated != 1 {
        return Err(ComponentAdministrationError::Conflict);
    }
    append_component_human_answer_audit(
        transaction,
        actor,
        decision_id,
        bot_id,
        component_name,
        arguments_hash,
        "component.human_expired",
        checkpoint_key,
    )
    .await
}

pub(crate) async fn commit_component_runtime(
    transaction: deadpool_postgres::Transaction<'_>,
    operation: &'static str,
) -> Result<(), ComponentAdministrationError> {
    transaction.commit().await.map_err(|error| {
        tracing::error!(operation, error = %error, "component runtime commit result unknown");
        ComponentAdministrationError::CommitUnknown
    })
}

fn decode_pending_human_decision(
    row: &Row,
) -> Result<PendingComponentHumanDecision, ComponentAdministrationError> {
    let decision_id: String = row
        .try_get("decision_id")
        .map_err(|_| corrupt("decision_id"))?;
    let run_id: String = row.try_get("run_id").map_err(|_| corrupt("run_id"))?;
    let provider_call_id: String = row
        .try_get("provider_call_id")
        .map_err(|_| corrupt("provider_call_id"))?;
    let agent_id: String = row.try_get("bot_id").map_err(|_| corrupt("agent_id"))?;
    let component_name: String = row
        .try_get("component_name")
        .map_err(|_| corrupt("component_name"))?;
    let arguments: serde_json::Value = row
        .try_get("arguments")
        .map_err(|_| corrupt("component_arguments"))?;
    for (value, field) in [
        (decision_id.as_str(), "decision_id"),
        (run_id.as_str(), "run_id"),
        (agent_id.as_str(), "agent_id"),
        (component_name.as_str(), "component_name"),
    ] {
        validate_name(value).map_err(|_| corrupt(field))?;
    }
    if provider_call_id.is_empty()
        || provider_call_id.len() > 1024
        || provider_call_id.as_bytes().contains(&0)
    {
        return Err(corrupt("provider_call_id"));
    }
    Ok(PendingComponentHumanDecision {
        decision_id,
        run_id: openbot_contracts::ids::RunId::new(run_id),
        provider_call_id,
        agent_id: openbot_contracts::ids::BotId::new(agent_id),
        component_name,
        arguments,
        requested_at: row
            .try_get("requested_at")
            .map_err(|_| corrupt("requested_at"))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| corrupt("expires_at"))?,
    })
}

fn decode_human_answer(
    value: Option<serde_json::Value>,
) -> Result<ComponentHumanDecisionAnswer, ComponentAdministrationError> {
    serde_json::from_value(value.ok_or_else(|| corrupt("decision_answer"))?)
        .map_err(|_| corrupt("decision_answer"))
}

fn validate_human_answer_against_arguments(
    component_name: &str,
    arguments: &serde_json::Value,
    answer: &ComponentHumanDecisionAnswer,
) -> Result<(), ComponentAdministrationError> {
    validate_component_human_decision_answer(component_name, arguments, answer).map_err(|_| {
        ComponentAdministrationError::InvalidInput {
            field: "component_answer",
        }
    })
}

fn decode_record(row: &Row) -> Result<ComponentRecord, ComponentAdministrationError> {
    let name: String = row.try_get("name").map_err(|_| corrupt("name"))?;
    let title: String = row.try_get("title").map_err(|_| corrupt("title"))?;
    let kind: String = row.try_get("kind").map_err(|_| corrupt("kind"))?;
    let draft_description: String = row
        .try_get("draft_description")
        .map_err(|_| corrupt("draft_description"))?;
    let published_description: Option<String> = row
        .try_get("published_description")
        .map_err(|_| corrupt("published_description"))?;
    let published: bool = row.try_get("published").map_err(|_| corrupt("published"))?;
    let published_at: Option<time::OffsetDateTime> = row
        .try_get("published_at")
        .map_err(|_| corrupt("published_at"))?;
    let updated_by: Option<String> = row
        .try_get("updated_by")
        .map_err(|_| corrupt("updated_by"))?;
    let updated_at: time::OffsetDateTime = row
        .try_get("updated_at")
        .map_err(|_| corrupt("updated_at"))?;
    let withheld_from: Vec<String> = row
        .try_get("withheld_from")
        .map_err(|_| corrupt("withheld_from"))?;
    let functions: Vec<String> = row.try_get("functions").map_err(|_| corrupt("functions"))?;
    validate_name(&name)?;
    validate_text(&title, 512, "title")?;
    validate_description(&draft_description, "draft_description")?;
    if let Some(value) = published_description.as_deref() {
        validate_description(value, "published_description")?;
    }
    if published && (published_description.is_none() || published_at.is_none()) {
        return Err(corrupt("publication"));
    }
    if let Some(value) = updated_by.as_deref() {
        validate_text(value, 512, "updated_by")?;
    }
    validate_identifiers(&withheld_from, "withheld_from")?;
    validate_identifiers(&functions, "functions")?;
    let kind = match kind.as_str() {
        "chart" => CompiledComponentKind::Chart,
        "card" => CompiledComponentKind::Card,
        "decision" => CompiledComponentKind::Decision,
        "sandboxed" => CompiledComponentKind::Sandboxed,
        _ => return Err(corrupt("kind")),
    };
    if kind == CompiledComponentKind::Sandboxed && !functions.is_empty() {
        return Err(corrupt("sandboxed_component_functions"));
    }
    let has_unpublished_changes =
        draft_description != published_description.as_deref().unwrap_or("");
    Ok(ComponentRecord {
        name,
        title,
        kind,
        draft_description,
        published_description,
        published,
        published_at,
        updated_by,
        updated_at,
        has_unpublished_changes,
        withheld_from,
        functions,
    })
}

fn validate_identifiers(
    values: &[String],
    field: &'static str,
) -> Result<(), ComponentAdministrationError> {
    if values.len() > 1024 {
        return Err(corrupt(field));
    }
    for value in values {
        validate_text(value, 512, field)?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), ComponentAdministrationError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(corrupt(field))
    } else {
        Ok(())
    }
}

fn validate_name(value: &str) -> Result<(), ComponentAdministrationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Err(corrupt("name"))
    } else {
        Ok(())
    }
}

fn validate_description(
    value: &str,
    field: &'static str,
) -> Result<(), ComponentAdministrationError> {
    if value.is_empty()
        || value.len() > MAX_COMPONENT_DESCRIPTION_BYTES
        || value.as_bytes().contains(&0)
    {
        Err(corrupt(field))
    } else {
        Ok(())
    }
}

fn corrupt(field: &'static str) -> ComponentAdministrationError {
    ComponentAdministrationError::Corrupt { field }
}

fn unavailable(error: crate::db::pool::PoolError) -> ComponentAdministrationError {
    tracing::warn!(error = %error, "component catalogue pool unavailable");
    ComponentAdministrationError::Unavailable
}

fn component_writer_error(error: crate::db::InfraError) -> ComponentAdministrationError {
    if crate::thread_history_writer::is_closed(&error) {
        return ComponentAdministrationError::NotVisible;
    }
    tracing::warn!(error=%error,"Component history writer admission failed");
    match error {
        crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
            ComponentAdministrationError::Unavailable
        }
        _ => ComponentAdministrationError::Corrupt {
            field: "thread_history_writer",
        },
    }
}

fn query_unavailable(error: tokio_postgres::Error) -> ComponentAdministrationError {
    if crate::thread_history_writer::is_closed_query(&error) {
        return ComponentAdministrationError::NotVisible;
    }
    tracing::warn!(error = %error, "component catalogue query unavailable");
    ComponentAdministrationError::Unavailable
}

fn infra_unavailable(error: crate::db::InfraError) -> ComponentAdministrationError {
    tracing::warn!(error = %error, "component catalogue audit unavailable");
    ComponentAdministrationError::Unavailable
}
