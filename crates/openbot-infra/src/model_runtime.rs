//! Explicit custom run acceptance. Source locks never grant later credential access.

use openbot_application::model_connections::normalize_model_configuration;
use openbot_application::{BeginThreadRunRequest, ThreadDirectoryError as Error};
use openbot_contracts::{command::ThreadRunAnchor, model_connections::CustomModelProtocol};
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

pub(crate) struct SelectionSnapshot {
    connection_id: Uuid,
    connection_revision: i64,
    secret_id: Uuid,
    protocol: CustomModelProtocol,
    endpoint: String,
    model: String,
}

fn corrupt() -> Error {
    Error::Corrupt {
        field: "model_selection",
    }
}
fn value<T: for<'a> tokio_postgres::types::FromSql<'a>>(row: &Row, name: &str) -> Result<T, Error> {
    row.try_get(name).map_err(|_| corrupt())
}

pub(crate) async fn validate_actor(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let Some(selection) = &request.command.model_selection else {
        return Ok(());
    };
    if !selection.is_valid() {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    let row = tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) FOR SHARE OF u",
        &[&request.actor.as_str(), &generation]).await.map_err(|_| Error::Unavailable)?;
    row.map(|_| ()).ok_or(Error::NotVisible)
}

/// Validate the new target before creating a thread; a visible remote target is a bad selection.
pub(crate) async fn validate_target(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let channel = match &request.command.anchor {
        ThreadRunAnchor::DirectBot => None,
        ThreadRunAnchor::Channel { channel_id } => Some(channel_id.as_str()),
    };
    let row = tx
        .query_opt(
            "SELECT a.type::text AS agent_type FROM public.agents a
        JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE a.id=$1 AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3)
          AND (p.visibility='public' OR p.owner_user_id=$2 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$2 AND ur.role='admin'))
          AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM public.channels c
            JOIN public.channel_memberships cm ON cm.channel_id=c.id AND cm.user_id=$2
            JOIN public.channel_agents ca ON ca.channel_id=c.id AND ca.agent_id=a.id
            LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
            WHERE c.id=$4 AND (c.package_id IS NULL OR cp.tenant_id=$3)))",
            &[
                &request.command.bot_id.as_str(),
                &request.actor.as_str(),
                &request.tenant.as_str(),
                &channel,
            ],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)?;
    if value::<String>(&row, "agent_type")? != "built_in" {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    Ok(())
}

/// Historical replay requires current thread visibility but does not reselect a source object.
pub(crate) async fn validate_thread(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<(), Error> {
    let visible: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM public.threads t
        WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.status<>'deleted'
        AND ((t.anchor_kind='direct_bot' AND EXISTS(SELECT 1 FROM public.thread_memberships tm
          WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) OR (t.anchor_kind='channel' AND EXISTS(
          SELECT 1 FROM public.channels c JOIN public.channel_memberships cm ON cm.channel_id=c.id
          LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
          WHERE c.id=t.anchor_id AND cm.user_id=$4 AND (c.package_id IS NULL OR cp.tenant_id=$3))))) AS visible",
        &[&request.command.thread_id.as_str(), &request.deployment.as_str(), &request.tenant.as_str(), &request.actor.as_str()])
        .await.map_err(|_| Error::Unavailable)?.try_get("visible").map_err(|_| corrupt())?;
    if !visible {
        return Err(Error::NotVisible);
    }
    Ok(())
}

/// Lock order after user/thread/lease/skills: connection, then its current active secret.
pub(crate) async fn resolve(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
) -> Result<Option<SelectionSnapshot>, Error> {
    let Some(selection) = &request.command.model_selection else {
        return Ok(None);
    };
    let id = Uuid::parse_str(&selection.connection_id).map_err(|_| Error::InvalidInput {
        field: "model_selection",
    })?;
    // Target, current membership, source ownership and source configuration share this SQL snapshot.
    let row = tx.query_opt("SELECT c.id,c.revision,c.current_secret_id,c.name,c.protocol,c.endpoint,c.model
        FROM public.model_connections c
        WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4
          AND c.deleted_at IS NULL AND c.enabled
          AND EXISTS(SELECT 1 FROM public.threads t JOIN public.agents a ON a.id=$6
            JOIN public.agent_profiles p ON p.agent_id=a.id
            LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
            WHERE t.thread_id=$5 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.status='active'
              AND a.type='built_in' AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3)
              AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(
                SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))
              AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(
                SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4))
                OR (t.anchor_kind='channel' AND EXISTS(SELECT 1 FROM public.channels ch
                  JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4
                  JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
                  LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
                  WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$3)))))
        FOR SHARE OF c", &[&id,&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str(),
            &request.command.thread_id.as_str(),&request.command.bot_id.as_str()])
        .await.map_err(|_| Error::Unavailable)?.ok_or(Error::NotVisible)?;
    let revision = value::<i64>(&row, "revision")?;
    if revision != selection.expected_revision {
        return Err(Error::RequestConflict);
    }
    let secret_id: Uuid = value(&row, "current_secret_id")?;
    tx.query_opt(
        "SELECT s.id FROM public.model_connection_secrets s
        WHERE s.id=$1 AND s.connection_id=$2 AND s.deployment_id=$3 AND s.tenant_id=$4
          AND s.owner_user_id=$5 AND s.retired_at IS NULL FOR SHARE OF s",
        &[
            &secret_id,
            &id,
            &request.deployment.as_str(),
            &request.tenant.as_str(),
            &request.actor.as_str(),
        ],
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .ok_or_else(corrupt)?;
    let protocol = match value::<String>(&row, "protocol")?.as_str() {
        "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
        "openai_responses" => CustomModelProtocol::OpenaiResponses,
        "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
        _ => return Err(corrupt()),
    };
    let endpoint: String = value(&row, "endpoint")?;
    let normalized = normalize_model_configuration(
        &value::<String>(&row, "name")?,
        protocol,
        &endpoint,
        &value::<String>(&row, "model")?,
        true,
    )
    .map_err(|_| corrupt())?;
    if normalized.endpoint != endpoint {
        return Err(corrupt());
    }
    Ok(Some(SelectionSnapshot {
        connection_id: id,
        connection_revision: revision,
        secret_id,
        protocol,
        endpoint,
        model: normalized.model,
    }))
}

pub(crate) async fn insert(
    tx: &Transaction<'_>,
    request: &BeginThreadRunRequest,
    snapshot: &SelectionSnapshot,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    let affected = tx.execute("INSERT INTO public.run_model_selections(run_id,deployment_id,tenant_id,owner_user_id,
        auth_generation,connection_id,connection_revision,secret_id,protocol,endpoint,model,created_at)
        SELECT r.run_id,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 FROM public.runs r
        JOIN public.threads t ON t.thread_id=r.thread_id WHERE r.run_id=$1 AND r.actor_id=$4
          AND t.deployment_id=$2 AND t.tenant_id=$3 AND r.thread_id=$13 AND r.bot_id=$14",
        &[&request.command.run_id.as_str(),&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str(),
          &generation,&snapshot.connection_id,&snapshot.connection_revision,&snapshot.secret_id,
          &snapshot.protocol.as_str(),&snapshot.endpoint,&snapshot.model,&now,
          &request.command.thread_id.as_str(),&request.command.bot_id.as_str()])
        .await.map_err(|_| Error::Unavailable)?;
    if affected != 1 {
        return Err(corrupt());
    }
    Ok(())
}

/// Current source material stays inside Infra. Ciphertext is never projected into a request.
pub(crate) struct LoadedSelection {
    pub(crate) binding: openbot_application::RunModelBinding,
    pub(crate) has_cost_cap: bool,
    pub(crate) encrypted_value: zeroize::Zeroizing<String>,
}

/// Read-only context validation takes no authority row locks and cannot authorize a send.
/// Each read ends before the next one; the final source statement repeats current actor predicates.
pub(crate) async fn load_selection_for_context(
    client: &tokio_postgres::Client,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<Option<openbot_application::RunModelBinding>, openbot_application::AgentContextError> {
    if classify_selection_storage(client, deployment, tenant, lease).await?
        == StoredSelectionKind::V2
    {
        return Err(openbot_application::AgentContextError::Corrupt {
            field: "model_dataset_binding",
        });
    }
    load_selection(
        client,
        deployment,
        tenant,
        lease,
        SelectionPurpose::ContextCheck,
    )
    .await
    .map(|value| value.map(|loaded| loaded.binding))
}

/// A real start owns a guarded transaction and takes user → connection → current secret SHARE.
/// Both immutable intent and snapshot must exist; neither missing half means a legacy route.
pub(crate) async fn load_current_selection(
    tx: &Transaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<Option<LoadedSelection>, openbot_application::AgentContextError> {
    if classify_selection_storage(tx, deployment, tenant, lease).await? == StoredSelectionKind::V2 {
        return Err(openbot_application::AgentContextError::Corrupt {
            field: "model_dataset_binding",
        });
    }
    load_selection(
        tx,
        deployment,
        tenant,
        lease,
        SelectionPurpose::AuthorizedStart,
    )
    .await
}

#[derive(Clone, Copy)]
enum SelectionPurpose {
    ContextCheck,
    AuthorizedStart,
}
impl SelectionPurpose {
    fn statement(self, query: &'static str, lock: &'static str) -> std::borrow::Cow<'static, str> {
        match self {
            Self::ContextCheck => std::borrow::Cow::Borrowed(query),
            Self::AuthorizedStart => std::borrow::Cow::Owned(format!("{query}{lock}")),
        }
    }
}

async fn load_selection<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
    purpose: SelectionPurpose,
) -> Result<Option<LoadedSelection>, openbot_application::AgentContextError> {
    use openbot_application::AgentContextError as ContextError;
    use openbot_contracts::model_connections::RunModelSelection;
    let bad = || ContextError::Corrupt {
        field: "model_selection",
    };
    let initial = tx.query_opt("SELECT s.*,
        coalesce(input.content ? 'modelSelection',false) AS has_intent,
        input.content->'modelSelection' AS intent,
        input.run_id AS input_run_id,input.thread_id AS input_thread_id,input.actor_id AS input_actor_id,
        input.role AS input_role
        FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
        LEFT JOIN public.messages input ON input.message_id=r.run_id||':input'
        LEFT JOIN public.run_model_selections s ON s.run_id=r.run_id
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4
          AND r.fencing_token=$5 AND r.status='running' AND t.deployment_id=$6 AND t.tenant_id=$7
          AND t.status='active'",
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str()])
        .await.map_err(|_| ContextError::Unavailable)?.ok_or(ContextError::Stale)?;
    // Detect explicit intent by exact input identity only. Corrupt metadata must never hide
    // the marker and turn a missing snapshot into a legacy route.
    let has_intent: bool = initial.try_get("has_intent").map_err(|_| bad())?;
    let snapshot_id: Option<String> = initial.try_get("run_id").map_err(|_| bad())?;
    if !has_intent && snapshot_id.is_none() {
        return Ok(None);
    }
    if !has_intent
        || snapshot_id.is_none()
        || initial
            .try_get::<_, Option<String>>("input_role")
            .map_err(|_| bad())?
            .as_deref()
            != Some("user")
    {
        return Err(bad());
    }
    let intent: serde_json::Value = initial.try_get("intent").map_err(|_| bad())?;
    let selection: RunModelSelection = serde_json::from_value(intent.clone()).map_err(|_| bad())?;
    let stored =
        crate::db::tables::run_model_selections::Row::try_from(&initial).map_err(|_| bad())?;
    let generation = u64::try_from(stored.auth_generation).map_err(|_| bad())?;
    if stored.run_id != lease.run_id().as_str()
        || stored.deployment_id != deployment.as_str()
        || stored.tenant_id != tenant.as_str()
        || stored.owner_user_id != lease.actor_id().as_str()
        || Uuid::parse_str(&selection.connection_id).map_err(|_| bad())? != stored.connection_id
        || selection.expected_revision != stored.connection_revision
        || initial
            .try_get::<_, Option<String>>("input_run_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.run_id().as_str())
        || initial
            .try_get::<_, Option<String>>("input_thread_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.thread_id().as_str())
        || initial
            .try_get::<_, Option<String>>("input_actor_id")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.actor_id().as_str())
    {
        return Err(bad());
    }
    tx.query_opt(purpose.statement("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))", " FOR SHARE OF u").as_ref(),
        &[&lease.actor_id().as_str(),&stored.auth_generation]).await.map_err(|_| ContextError::Unavailable)?
        .ok_or(ContextError::Stale)?;
    let current = tx.query_opt(purpose.statement("SELECT c.name,c.protocol,c.endpoint,c.model,
        (r.budget_cost_currency IS NOT NULL OR r.budget_max_cost_micro_units IS NOT NULL) AS has_cost_cap
        FROM public.model_connections c
        JOIN public.run_model_selections s ON s.connection_id=c.id AND s.run_id=$1
        JOIN public.runs r ON r.run_id=s.run_id JOIN public.threads t ON t.thread_id=r.thread_id
        JOIN public.messages input ON input.message_id=r.run_id||':input'
        JOIN public.agents a ON a.id=r.bot_id JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 AND r.fencing_token=$5
          AND r.status='running' AND t.deployment_id=$6 AND t.tenant_id=$7 AND t.status='active'
          AND EXISTS(SELECT 1 FROM public.users u WHERE u.id=$4 AND coalesce(u.auth_generation,0)=$8
            AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
            AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)))
          AND EXISTS(SELECT 1 FROM public.thread_leases l WHERE l.thread_id=t.thread_id
            AND l.fencing_token=r.fencing_token AND l.expires_at>clock_timestamp())
          AND input.role='user' AND input.run_id=r.run_id AND input.thread_id=t.thread_id AND input.actor_id=r.actor_id
          AND input.content->'modelSelection'=$15::jsonb
          AND s.deployment_id=$6 AND s.tenant_id=$7 AND s.owner_user_id=$4 AND s.auth_generation=$8
          AND s.connection_id=$9 AND s.connection_revision=$10 AND s.secret_id=$11
          AND s.protocol=$12 AND s.endpoint=$13 AND s.model=$14 AND s.created_at=r.created_at
          AND c.deployment_id=$6 AND c.tenant_id=$7 AND c.owner_user_id=$4
          AND c.revision=s.connection_revision AND c.current_secret_id=s.secret_id
          AND c.protocol=s.protocol AND c.endpoint=s.endpoint AND c.model=s.model
          AND c.enabled AND c.deleted_at IS NULL
          AND a.type='built_in' AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$7)
          AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))
          AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(
            SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$4))
            OR (t.anchor_kind='channel' AND EXISTS(SELECT 1 FROM public.channels ch
              JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4
              JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
              LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
              WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$7))))
        ", " FOR SHARE OF c").as_ref(),
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str(),&stored.auth_generation,&stored.connection_id,
          &stored.connection_revision,&stored.secret_id,&stored.protocol,&stored.endpoint,&stored.model,&intent])
        .await.map_err(|_| ContextError::Unavailable)?.ok_or(ContextError::Stale)?;
    let secret = tx
        .query_opt(
            purpose
                .statement(
                    "SELECT s.encrypted_value FROM public.model_connection_secrets s
        WHERE s.id=$1 AND s.connection_id=$2 AND s.deployment_id=$3 AND s.tenant_id=$4
          AND s.owner_user_id=$5 AND s.retired_at IS NULL",
                    " FOR SHARE OF s",
                )
                .as_ref(),
            &[
                &stored.secret_id,
                &stored.connection_id,
                &deployment.as_str(),
                &tenant.as_str(),
                &lease.actor_id().as_str(),
            ],
        )
        .await
        .map_err(|_| ContextError::Unavailable)?
        .ok_or(ContextError::Stale)?;
    let protocol = match stored.protocol.as_str() {
        "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
        "openai_responses" => CustomModelProtocol::OpenaiResponses,
        "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
        _ => return Err(bad()),
    };
    let name: String = current.try_get("name").map_err(|_| bad())?;
    let normalized =
        normalize_model_configuration(&name, protocol, &stored.endpoint, &stored.model, true)
            .map_err(|_| bad())?;
    if normalized.endpoint != stored.endpoint {
        return Err(bad());
    }
    let binding = openbot_application::RunModelBinding::from_verified_snapshot(
        lease,
        deployment.clone(),
        tenant.clone(),
        openbot_contracts::auth::AuthGeneration::new(generation),
        selection,
        stored.secret_id.to_string(),
        normalized,
    )?;
    Ok(Some(LoadedSelection {
        binding,
        has_cost_cap: current.try_get("has_cost_cap").map_err(|_| bad())?,
        encrypted_value: zeroize::Zeroizing::new(
            secret.try_get("encrypted_value").map_err(|_| bad())?,
        ),
    }))
}

/// This classification only chooses a reader. It never establishes model authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoredSelectionKind {
    None,
    Legacy,
    V2,
}

pub(crate) async fn classify_selection_storage<C: tokio_postgres::GenericClient + Sync>(
    tx: &C,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<StoredSelectionKind, openbot_application::AgentContextError> {
    use openbot_application::AgentContextError as E;
    use openbot_contracts::versioned_model_selection::VersionedRunModelSelection;
    let bad = || E::Corrupt {
        field: "model_selection_storage",
    };
    let row = tx
        .query_opt(
            "SELECT
        coalesce(m.content ? 'modelSelection',false) AS has_intent,
        m.content->'modelSelection' AS intent,m.role AS input_role,
        m.run_id AS input_run,m.thread_id AS input_thread,m.actor_id AS input_actor,
        EXISTS(SELECT 1 FROM public.run_model_selections s WHERE s.run_id=r.run_id) AS has_v1
        FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
        LEFT JOIN public.messages m ON m.message_id=r.run_id||':input'
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4
          AND r.fencing_token=$5 AND r.status='running' AND t.deployment_id=$6
          AND t.tenant_id=$7 AND t.status='active'",
            &[
                &lease.run_id().as_str(),
                &lease.thread_id().as_str(),
                &lease.bot_id().as_str(),
                &lease.actor_id().as_str(),
                &lease.fencing().get(),
                &deployment.as_str(),
                &tenant.as_str(),
            ],
        )
        .await
        .map_err(|_| E::Unavailable)?
        .ok_or(E::Stale)?;
    // Old constructors may still be used against an older supported native prefix. The
    // new table's absence cannot itself turn a v2 marker into an unselected route.
    let exists: bool = tx
        .query_one(
            "SELECT to_regclass('openbot_internal.run_model_selection_v2_snapshots') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|_| E::Unavailable)?
        .try_get(0)
        .map_err(|_| bad())?;
    let has_v2: bool = if exists {
        tx.query_one("SELECT EXISTS(SELECT 1 FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1)",
            &[&lease.run_id().as_str()]).await.map_err(|_| E::Unavailable)?
            .try_get(0).map_err(|_| bad())?
    } else {
        false
    };
    let has_v1: bool = row.try_get("has_v1").map_err(|_| bad())?;
    let has_intent: bool = row.try_get("has_intent").map_err(|_| bad())?;
    // Old unselected runs can carry their real user input under any message ID.
    // Only explicit-selection storage requires the new exact run_id:input identity.
    if !has_intent && !has_v1 && !has_v2 {
        return Ok(StoredSelectionKind::None);
    }
    if row
        .try_get::<_, Option<String>>("input_role")
        .map_err(|_| bad())?
        .as_deref()
        != Some("user")
        || row
            .try_get::<_, Option<String>>("input_run")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.run_id().as_str())
        || row
            .try_get::<_, Option<String>>("input_thread")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.thread_id().as_str())
        || row
            .try_get::<_, Option<String>>("input_actor")
            .map_err(|_| bad())?
            .as_deref()
            != Some(lease.actor_id().as_str())
    {
        return Err(bad());
    }
    if !has_intent || has_v1 == has_v2 {
        return Err(bad());
    }
    let intent: serde_json::Value = row.try_get("intent").map_err(|_| bad())?;
    let selection: VersionedRunModelSelection =
        serde_json::from_value(intent).map_err(|_| bad())?;
    match selection {
        VersionedRunModelSelection::V1(value) if has_v1 && value.is_valid() => Ok(StoredSelectionKind::Legacy),
        VersionedRunModelSelection::V2(value) if has_v2
            && value.source()==openbot_contracts::versioned_model_selection::ModelSelectionIntentSource::Custom
            => Ok(StoredSelectionKind::V2),
        _ => Err(bad()),
    }
}

pub(crate) async fn validate_actor_v2(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
) -> Result<(), Error> {
    use openbot_contracts::versioned_model_selection::{
        ModelSelectionIntentSource, VersionedRunModelSelection,
    };
    if request.command.model_selection.source() != ModelSelectionIntentSource::Custom
        || !VersionedRunModelSelection::V2(request.command.model_selection.clone()).is_valid()
    {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email)) FOR SHARE OF u",
        &[&request.actor.as_str(),&generation]).await.map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)?;
    if !lock_v2_roles(
        tx,
        request.actor.as_str(),
        SelectionPurpose::AuthorizedStart,
    )
    .await
    .map_err(|_| Error::Unavailable)?
    {
        return Err(Error::NotVisible);
    }
    Ok(())
}

// Only current positive authority rows are locked. An absence (revoked_access) is
// observed again in the final single-statement predicate, never called a row lock.
async fn lock_v2_roles(
    tx: &Transaction<'_>,
    actor: &str,
    purpose: SelectionPurpose,
) -> Result<bool, tokio_postgres::Error> {
    tx.query(
        purpose
            .statement(
                "SELECT ur.role FROM public.user_roles ur
        WHERE ur.user_id=$1 AND ur.role IN ('user','admin') ORDER BY ur.role",
                " FOR SHARE OF ur",
            )
            .as_ref(),
        &[&actor],
    )
    .await
    .map(|rows| !rows.is_empty())
}

async fn lock_v2_agent_package(
    tx: &Transaction<'_>,
    bot: &str,
    tenant: &str,
    packaged: bool,
    purpose: SelectionPurpose,
) -> Result<bool, tokio_postgres::Error> {
    if !packaged {
        return Ok(true);
    }
    tx.query_opt(
        purpose
            .statement(
                "SELECT dp.id FROM public.deployment_packages dp
        JOIN public.agents a ON a.package_id=dp.id
        WHERE a.id=$1 AND dp.tenant_id=$2",
                " FOR SHARE OF dp",
            )
            .as_ref(),
        &[&bot, &tenant],
    )
    .await
    .map(|row| row.is_some())
}

async fn lock_v2_anchor_membership(
    tx: &Transaction<'_>,
    bot: &str,
    actor: &str,
    tenant: &str,
    thread: Option<&str>,
    channel: Option<&str>,
    purpose: SelectionPurpose,
) -> Result<bool, tokio_postgres::Error> {
    if let Some(channel) = channel {
        let row = tx
            .query_opt(
                purpose
                    .statement(
                        "SELECT c.package_id IS NOT NULL AS packaged
            FROM public.channels c
            JOIN public.channel_memberships cm ON cm.channel_id=c.id AND cm.user_id=$2
            JOIN public.channel_agents ca ON ca.channel_id=c.id AND ca.agent_id=$3
            LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
            WHERE c.id=$1 AND (c.package_id IS NULL OR cp.tenant_id=$4)",
                        " FOR SHARE OF c,cm,ca",
                    )
                    .as_ref(),
                &[&channel, &actor, &bot, &tenant],
            )
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let packaged: bool = row.get("packaged");
        if packaged {
            return tx
                .query_opt(
                    purpose
                        .statement(
                            "SELECT cp.id FROM public.deployment_packages cp
                JOIN public.channels c ON c.package_id=cp.id WHERE c.id=$1 AND cp.tenant_id=$2",
                            " FOR SHARE OF cp",
                        )
                        .as_ref(),
                    &[&channel, &tenant],
                )
                .await
                .map(|row| row.is_some());
        }
    } else if let Some(thread) = thread {
        return tx
            .query_opt(
                purpose
                    .statement(
                        "SELECT tm.thread_id FROM public.thread_memberships tm
            WHERE tm.thread_id=$1 AND tm.user_id=$2",
                        " FOR SHARE OF tm",
                    )
                    .as_ref(),
                &[&thread, &actor],
            )
            .await
            .map(|row| row.is_some());
    }
    Ok(true)
}

pub(crate) async fn validate_target_v2(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
) -> Result<(), Error> {
    let channel = match &request.command.anchor {
        ThreadRunAnchor::DirectBot => None,
        ThreadRunAnchor::Channel { channel_id } => Some(channel_id.as_str()),
    };
    let row = tx
        .query_opt(
            "SELECT a.type::text AS agent_type,a.package_id IS NOT NULL AS packaged
        FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE a.id=$1 AND p.deleted_at IS NULL AND (a.package_id IS NULL OR dp.tenant_id=$3)
          AND (p.visibility='public' OR p.owner_user_id=$2 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$2 AND ur.role='admin'))
        FOR SHARE OF a,p",
            &[
                &request.command.bot_id.as_str(),
                &request.actor.as_str(),
                &request.tenant.as_str(),
            ],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)?;
    if value::<String>(&row, "agent_type")? != "built_in" {
        return Err(Error::InvalidInput {
            field: "model_selection",
        });
    }
    let existing_thread = tx
        .query_opt(
            "SELECT t.thread_id FROM public.threads t WHERE t.thread_id=$1",
            &[&request.command.thread_id.as_str()],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .is_some();
    if !lock_v2_agent_package(
        tx,
        request.command.bot_id.as_str(),
        request.tenant.as_str(),
        value(&row, "packaged")?,
        SelectionPurpose::AuthorizedStart,
    )
    .await
    .map_err(|_| Error::Unavailable)?
        || !lock_v2_anchor_membership(
            tx,
            request.command.bot_id.as_str(),
            request.actor.as_str(),
            request.tenant.as_str(),
            existing_thread.then_some(request.command.thread_id.as_str()),
            channel,
            SelectionPurpose::AuthorizedStart,
        )
        .await
        .map_err(|_| Error::Unavailable)?
    {
        return Err(Error::NotVisible);
    }
    Ok(())
}

pub(crate) async fn validate_thread_v2(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
) -> Result<(), Error> {
    let visible:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM public.threads t
        WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.status<>'deleted'
        AND ((t.anchor_kind='direct_bot' AND t.anchor_id=$5 AND EXISTS(SELECT 1 FROM public.thread_memberships tm
          WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) OR (t.anchor_kind='channel' AND EXISTS(
          SELECT 1 FROM public.channels c JOIN public.channel_memberships cm ON cm.channel_id=c.id
          LEFT JOIN public.deployment_packages cp ON cp.id=c.package_id
          WHERE c.id=t.anchor_id AND cm.user_id=$4 AND (c.package_id IS NULL OR cp.tenant_id=$3))))) AS visible",
        &[&request.command.thread_id.as_str(),&request.deployment.as_str(),&request.tenant.as_str(),
            &request.actor.as_str(),&request.command.bot_id.as_str()])
        .await.map_err(|_|Error::Unavailable)?.try_get("visible").map_err(|_|corrupt())?;
    if !visible {
        return Err(Error::NotVisible);
    }
    // Actual target/membership locks are acquired together in validate_target_v2,
    // in the same order used by start, before any connection lock.

    Ok(())
}

pub(crate) struct SelectionSnapshotV2 {
    common: SelectionSnapshot,
    model_id: String,
    catalog_revision: i64,
}

pub(crate) async fn resolve_v2(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
) -> Result<SelectionSnapshotV2, Error> {
    let selection = &request.command.model_selection;
    let id = Uuid::parse_str(selection.connection_id()).map_err(|_| Error::InvalidInput {
        field: "model_selection",
    })?;
    let row = tx
        .query_opt(
            "SELECT c.id,c.revision,c.current_secret_id,c.name,c.protocol,c.endpoint,c.model
        FROM public.model_connections c WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3
          AND c.owner_user_id=$4 AND c.enabled AND c.deleted_at IS NULL FOR SHARE OF c",
            &[
                &id,
                &request.deployment.as_str(),
                &request.tenant.as_str(),
                &request.actor.as_str(),
            ],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or(Error::NotVisible)?;
    let revision: i64 = value(&row, "revision")?;
    if revision != selection.expected_connection_revision() {
        return Err(Error::RequestConflict);
    }
    let secret_id: Uuid = value(&row, "current_secret_id")?;
    let protocol_text: String = value(&row, "protocol")?;
    let protocol = protocol_from_text(&protocol_text).map_err(|_| corrupt())?;
    let endpoint: String = value(&row, "endpoint")?;
    let model: String = value(&row, "model")?;
    let catalog=tx.query_opt("SELECT model_id,catalog_revision,protocol,endpoint,model FROM public.custom_model_catalogs
        WHERE connection_id=$1 AND deployment_id=$2 AND tenant_id=$3 AND owner_user_id=$4
          AND enabled AND NOT retired FOR SHARE",
        &[&id,&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str()])
        .await.map_err(|_|Error::Unavailable)?.ok_or(Error::NotVisible)?;
    let model_id: String = value(&catalog, "model_id")?;
    let catalog_revision: i64 = value(&catalog, "catalog_revision")?;
    if model_id != selection.model_id() || catalog_revision != selection.expected_catalog_revision()
    {
        return Err(Error::RequestConflict);
    }
    if model_id != format!("custom:{id}")
        || value::<String>(&catalog, "protocol")? != protocol_text
        || value::<String>(&catalog, "endpoint")? != endpoint
        || value::<String>(&catalog, "model")? != model
    {
        return Err(corrupt());
    }
    tx.query_opt("SELECT s.id FROM public.model_connection_secrets s WHERE s.id=$1 AND s.connection_id=$2
        AND s.deployment_id=$3 AND s.tenant_id=$4 AND s.owner_user_id=$5 AND s.retired_at IS NULL FOR SHARE OF s",
        &[&secret_id,&id,&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str()])
        .await.map_err(|_|Error::Unavailable)?.ok_or_else(corrupt)?;
    let normalized = normalize_model_configuration(
        &value::<String>(&row, "name")?,
        protocol,
        &endpoint,
        &model,
        true,
    )
    .map_err(|_| corrupt())?;
    if normalized.endpoint != endpoint || normalized.model != model {
        return Err(corrupt());
    }
    Ok(SelectionSnapshotV2 {
        common: SelectionSnapshot {
            connection_id: id,
            connection_revision: revision,
            secret_id,
            protocol,
            endpoint,
            model,
        },
        model_id,
        catalog_revision,
    })
}

// Recheck the current conjunction in one RC statement after the original dataset
// verifier has locked its tuple and Local canary. These are observations only: all
// positive authority locks were acquired earlier in the canonical order. In
// particular, an inserted revoked_access row is not protected by an absence lock.
struct FinalV2Authority<'a> {
    deployment: &'a str,
    tenant: &'a str,
    actor: &'a str,
    auth_generation: i64,
    thread: &'a str,
    bot: &'a str,
    anchor_kind: &'a str,
    anchor_id: &'a str,
    fencing: i64,
    run: Option<&'a str>,
    connection_id: &'a Uuid,
    connection_revision: i64,
    secret_id: &'a Uuid,
    protocol: &'a str,
    endpoint: &'a str,
    model: &'a str,
    model_id: &'a str,
    catalog_revision: i64,
    dataset: &'a crate::model_dataset::ModelDatasetFacts,
}

async fn verify_final_v2_authority(
    tx: &Transaction<'_>,
    current: FinalV2Authority<'_>,
) -> Result<bool, tokio_postgres::Error> {
    let c = current;
    tx.query_one("SELECT EXISTS(
        SELECT 1 FROM public.users u
        JOIN public.threads t ON t.thread_id=$5
        JOIN public.thread_leases l ON l.thread_id=t.thread_id AND l.fencing_token=$9
        JOIN public.agents a ON a.id=$6
        JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        JOIN public.model_connections mc ON mc.id=$11
        JOIN public.custom_model_catalogs cc ON cc.connection_id=mc.id
        JOIN public.model_connection_secrets ms ON ms.id=$13 AND ms.connection_id=mc.id
        JOIN openbot_internal.artifact_dataset_bindings d ON d.deployment_id=$1 AND d.tenant_id=$2
        WHERE u.id=$3 AND coalesce(u.auth_generation,0)=$4
          AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
          AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))
          AND t.deployment_id=$1 AND t.tenant_id=$2 AND t.status='active'
          AND t.anchor_kind=$7 AND t.anchor_id=$8 AND l.expires_at>clock_timestamp()
          AND a.type='built_in' AND p.deleted_at IS NULL
          AND (a.package_id IS NULL OR dp.tenant_id=$2)
          AND (p.visibility='public' OR p.owner_user_id=$3 OR EXISTS(
            SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$3 AND ur.role='admin'))
          AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(
            SELECT 1 FROM public.thread_memberships tm WHERE tm.thread_id=t.thread_id AND tm.user_id=$3))
            OR (t.anchor_kind='channel' AND EXISTS(
            SELECT 1 FROM public.channels ch JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$3
            JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
            LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
            WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$2))))
          AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM public.runs r
            WHERE r.run_id=$10 AND r.thread_id=t.thread_id AND r.bot_id=a.id AND r.actor_id=u.id
              AND r.fencing_token=l.fencing_token AND r.status='running'))
          AND mc.deployment_id=$1 AND mc.tenant_id=$2 AND mc.owner_user_id=$3 AND mc.revision=$12
          AND mc.current_secret_id=ms.id AND mc.protocol=$14 AND mc.endpoint=$15 AND mc.model=$16
          AND mc.enabled AND mc.deleted_at IS NULL
          AND cc.deployment_id=$1 AND cc.tenant_id=$2 AND cc.owner_user_id=$3
          AND cc.model_id=$17 AND cc.catalog_revision=$18 AND cc.protocol=mc.protocol
          AND cc.endpoint=mc.endpoint AND cc.model=mc.model AND cc.enabled AND NOT cc.retired
          AND ms.deployment_id=$1 AND ms.tenant_id=$2 AND ms.owner_user_id=$3 AND ms.retired_at IS NULL
          AND d.dataset_id=$19 AND d.binding_schema=$20 AND d.initial_origin=$21 AND d.created_at=$22
        ) AS current", &[
            &c.deployment,&c.tenant,&c.actor,&c.auth_generation,&c.thread,&c.bot,
            &c.anchor_kind,&c.anchor_id,&c.fencing,&c.run,&c.connection_id,&c.connection_revision,
            &c.secret_id,&c.protocol,&c.endpoint,&c.model,&c.model_id,&c.catalog_revision,
            &c.dataset.dataset_id(),&c.dataset.binding_schema(),&c.dataset.initial_origin().as_str(),
            &c.dataset.created_at(),
        ]).await.map(|row| row.get("current"))
}

pub(crate) async fn verify_accept_v2_current(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
    snapshot: &SelectionSnapshotV2,
    dataset: &crate::model_dataset::ModelDatasetFacts,
    fencing: i64,
) -> Result<(), Error> {
    let (anchor_kind, anchor_id) = match &request.command.anchor {
        ThreadRunAnchor::DirectBot => ("direct_bot", request.command.bot_id.as_str()),
        ThreadRunAnchor::Channel { channel_id } => ("channel", channel_id.as_str()),
    };
    let c = &snapshot.common;
    if !verify_final_v2_authority(
        tx,
        FinalV2Authority {
            deployment: request.deployment.as_str(),
            tenant: request.tenant.as_str(),
            actor: request.actor.as_str(),
            auth_generation: i64::try_from(request.auth_generation.get())
                .map_err(|_| Error::NotVisible)?,
            thread: request.command.thread_id.as_str(),
            bot: request.command.bot_id.as_str(),
            anchor_kind,
            anchor_id,
            fencing,
            run: None,
            connection_id: &c.connection_id,
            connection_revision: c.connection_revision,
            secret_id: &c.secret_id,
            protocol: c.protocol.as_str(),
            endpoint: &c.endpoint,
            model: &c.model,
            model_id: &snapshot.model_id,
            catalog_revision: snapshot.catalog_revision,
            dataset,
        },
    )
    .await
    .map_err(|_| Error::Unavailable)?
    {
        return Err(Error::NotVisible);
    }
    Ok(())
}

pub(crate) async fn insert_v2(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
    snapshot: &SelectionSnapshotV2,
    dataset: &crate::model_dataset::ModelDatasetFacts,
    now: OffsetDateTime,
) -> Result<(), Error> {
    let s = &snapshot.common;
    let generation = i64::try_from(request.auth_generation.get()).map_err(|_| Error::NotVisible)?;
    let affected=tx.execute("INSERT INTO openbot_internal.run_model_selection_v2_snapshots(
        run_id,deployment_id,tenant_id,owner_user_id,auth_generation,connection_id,connection_revision,
        secret_id,protocol,endpoint,model,created_at,snapshot_schema,source,model_id,catalog_revision,
        dataset_id,dataset_binding_schema,dataset_initial_origin,dataset_binding_created_at,credential_policy)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,2,'custom',$13,$14,$15,$16,$17,$18,'custom_fixed_secret_revision_v1')",
        &[&request.command.run_id.as_str(),&request.deployment.as_str(),&request.tenant.as_str(),&request.actor.as_str(),
          &generation,&s.connection_id,&s.connection_revision,&s.secret_id,&s.protocol.as_str(),&s.endpoint,&s.model,&now,
          &snapshot.model_id,&snapshot.catalog_revision,&dataset.dataset_id(),&dataset.binding_schema(),
          &dataset.initial_origin().as_str(),&dataset.created_at()]).await.map_err(|_|Error::Unavailable)?;
    if affected != 1 {
        return Err(corrupt());
    }
    Ok(())
}

pub(crate) async fn verify_v2_replay_snapshot(
    tx: &Transaction<'_>,
    request: &openbot_application::BeginThreadRunV2Request,
    dataset: &crate::model_dataset::ModelDatasetFacts,
    created_at: OffsetDateTime,
) -> Result<(), Error> {
    let old: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.run_model_selections WHERE run_id=$1)",
            &[&request.command.run_id.as_str()],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .try_get(0)
        .map_err(|_| corrupt())?;
    if old {
        return Err(Error::RequestConflict);
    }
    let row = tx
        .query_opt(
            "SELECT * FROM openbot_internal.run_model_selection_v2_snapshots WHERE run_id=$1",
            &[&request.command.run_id.as_str()],
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .ok_or_else(corrupt)?;
    let stored = crate::db::tables::run_model_selection_v2_snapshots::Row::try_from(&row)
        .map_err(|_| corrupt())?;
    let intent = &request.command.model_selection;
    if stored.run_id != request.command.run_id.as_str()
        || stored.deployment_id != request.deployment.as_str()
        || stored.tenant_id != request.tenant.as_str()
        || stored.owner_user_id != request.actor.as_str()
        || stored.auth_generation < 0
        || stored.connection_id != Uuid::parse_str(intent.connection_id()).map_err(|_| corrupt())?
        || stored.connection_revision != intent.expected_connection_revision()
        || stored.snapshot_schema != 2
        || stored.source != "custom"
        || stored.model_id != intent.model_id()
        || stored.model_id != format!("custom:{}", stored.connection_id)
        || stored.catalog_revision != intent.expected_catalog_revision()
        || stored.created_at != created_at
        || stored.dataset_id != dataset.dataset_id()
        || stored.dataset_binding_schema != dataset.binding_schema()
        || stored.dataset_initial_origin != dataset.initial_origin().as_str()
        || stored.dataset_binding_created_at != dataset.created_at()
        || stored.credential_policy != "custom_fixed_secret_revision_v1"
    {
        return Err(corrupt());
    }
    Ok(())
}

fn protocol_from_text(
    value: &str,
) -> Result<CustomModelProtocol, openbot_application::AgentContextError> {
    match value {
        "openai_chat_completions" => Ok(CustomModelProtocol::OpenaiChatCompletions),
        "openai_responses" => Ok(CustomModelProtocol::OpenaiResponses),
        "anthropic_messages" => Ok(CustomModelProtocol::AnthropicMessages),
        _ => Err(openbot_application::AgentContextError::Corrupt {
            field: "model_selection",
        }),
    }
}

pub(crate) async fn load_v2_for_context(
    transaction: &crate::model_dataset::ModelDatasetTransaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<openbot_application::RunModelBinding, openbot_application::AgentContextError> {
    load_current_v2(
        transaction,
        deployment,
        tenant,
        lease,
        SelectionPurpose::ContextCheck,
    )
    .await
    .map(|loaded| loaded.binding)
}

pub(crate) async fn load_v2_for_start(
    transaction: &crate::model_dataset::ModelDatasetTransaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
) -> Result<LoadedSelection, openbot_application::AgentContextError> {
    load_current_v2(
        transaction,
        deployment,
        tenant,
        lease,
        SelectionPurpose::AuthorizedStart,
    )
    .await
}

async fn load_current_v2(
    transaction: &crate::model_dataset::ModelDatasetTransaction<'_>,
    deployment: &openbot_contracts::ids::DeploymentId,
    tenant: &openbot_contracts::ids::TenantId,
    lease: &openbot_application::RunExecutionLease,
    purpose: SelectionPurpose,
) -> Result<LoadedSelection, openbot_application::AgentContextError> {
    use openbot_application::{
        AgentContextError as E, RunModelBinding, RunModelCredentialPolicy, RunModelDatasetSnapshot,
        RunModelV2Snapshot,
    };
    use openbot_contracts::versioned_model_selection::{
        ModelSelectionIntentSource, RunModelSelectionV2,
    };
    let bad = || E::Corrupt {
        field: "model_selection_v2",
    };
    let tx = transaction.as_transaction();
    if classify_selection_storage(tx, deployment, tenant, lease).await? != StoredSelectionKind::V2 {
        return Err(bad());
    }
    let row=tx.query_opt("SELECT s.*,r.created_at AS run_created_at,m.content AS input_content,
        t.anchor_kind,t.anchor_id,
        (r.budget_cost_currency IS NOT NULL OR r.budget_max_cost_micro_units IS NOT NULL) AS has_cost_cap
        FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
        JOIN openbot_internal.run_model_selection_v2_snapshots s ON s.run_id=r.run_id
        JOIN public.messages m ON m.message_id=r.run_id||':input'
        WHERE r.run_id=$1 AND r.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 AND r.fencing_token=$5
          AND r.status='running' AND t.status='active' AND t.deployment_id=$6 AND t.tenant_id=$7
          AND m.role='user' AND m.run_id=r.run_id AND m.thread_id=t.thread_id AND m.actor_id=r.actor_id",
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str()])
        .await.map_err(|_|E::Unavailable)?.ok_or(E::Stale)?;
    let s = crate::db::tables::run_model_selection_v2_snapshots::Row::try_from(&row)
        .map_err(|_| bad())?;
    let input: serde_json::Value = row.try_get("input_content").map_err(|_| bad())?;
    let object = input.as_object().ok_or_else(bad)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "text" | "modelSelection" | "runAnchor" | "selectedSkillSlugs" | "artifactRefs"
        )
    }) || object
        .get("text")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return Err(bad());
    }
    if let Some(value) = object.get("selectedSkillSlugs") {
        let skills: Vec<String> = serde_json::from_value(value.clone()).map_err(|_| bad())?;
        if !openbot_contracts::command::valid_selected_skill_slugs(&skills) {
            return Err(bad());
        }
    }
    if let Some(value) = object.get("artifactRefs") {
        let refs: Vec<String> = serde_json::from_value(value.clone()).map_err(|_| bad())?;
        crate::thread_directory::artifact_refs::validate_ids(&refs).map_err(|_| bad())?;
    }
    let intent_value = input.get("modelSelection").cloned().ok_or_else(bad)?;
    let selection: RunModelSelectionV2 = serde_json::from_value(intent_value).map_err(|_| bad())?;
    let anchor: ThreadRunAnchor =
        serde_json::from_value(input.get("runAnchor").cloned().ok_or_else(bad)?)
            .map_err(|_| bad())?;
    let anchor_kind: String = row.try_get("anchor_kind").map_err(|_| bad())?;
    let anchor_id: String = row.try_get("anchor_id").map_err(|_| bad())?;
    let anchor_matches = match anchor {
        ThreadRunAnchor::DirectBot => {
            anchor_kind == "direct_bot" && anchor_id == lease.bot_id().as_str()
        }
        ThreadRunAnchor::Channel { channel_id } => {
            anchor_kind == "channel" && anchor_id == channel_id.as_str()
        }
    };
    let generation = u64::try_from(s.auth_generation).map_err(|_| bad())?;
    if !anchor_matches
        || selection.source() != ModelSelectionIntentSource::Custom
        || s.snapshot_schema != 2
        || s.source != "custom"
        || s.run_id != lease.run_id().as_str()
        || s.deployment_id != deployment.as_str()
        || s.tenant_id != tenant.as_str()
        || s.owner_user_id != lease.actor_id().as_str()
        || Uuid::parse_str(selection.connection_id()).map_err(|_| bad())? != s.connection_id
        || selection.expected_connection_revision() != s.connection_revision
        || selection.model_id() != s.model_id
        || selection.expected_catalog_revision() != s.catalog_revision
        || s.model_id != format!("custom:{}", s.connection_id)
        || s.created_at
            != row
                .try_get::<_, OffsetDateTime>("run_created_at")
                .map_err(|_| bad())?
        || s.credential_policy != "custom_fixed_secret_revision_v1"
    {
        return Err(bad());
    }

    // Both consumers keep the same SQL order. Context omits authority locks and projects
    // immutable values only; start acquires all current authority in its original Tx.
    tx.query_opt(purpose.statement("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2
        AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=u.id AND ur.role IN ('user','admin'))
        AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(u.email))", " FOR SHARE OF u").as_ref(),
        &[&lease.actor_id().as_str(),&s.auth_generation]).await.map_err(|_|E::Unavailable)?.ok_or(E::Stale)?;
    if !lock_v2_roles(tx, lease.actor_id().as_str(), purpose)
        .await
        .map_err(|_| E::Unavailable)?
    {
        return Err(E::Stale);
    }
    let target = tx.query_opt(purpose.statement("SELECT t.thread_id,a.package_id IS NOT NULL AS packaged FROM public.threads t JOIN public.runs r ON r.thread_id=t.thread_id
        JOIN public.thread_leases l ON l.thread_id=t.thread_id AND l.fencing_token=r.fencing_token
        JOIN public.agents a ON a.id=r.bot_id JOIN public.agent_profiles p ON p.agent_id=a.id
        LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id
        WHERE r.run_id=$1 AND t.thread_id=$2 AND r.bot_id=$3 AND r.actor_id=$4 AND r.fencing_token=$5
          AND r.status='running' AND t.status='active' AND t.deployment_id=$6 AND t.tenant_id=$7
          AND l.expires_at>clock_timestamp() AND a.type='built_in' AND p.deleted_at IS NULL
          AND (a.package_id IS NULL OR dp.tenant_id=$7)
          AND (p.visibility='public' OR p.owner_user_id=$4 OR EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=$4 AND ur.role='admin'))
          AND ((t.anchor_kind='direct_bot' AND t.anchor_id=a.id AND EXISTS(SELECT 1 FROM public.thread_memberships tm
            WHERE tm.thread_id=t.thread_id AND tm.user_id=$4)) OR (t.anchor_kind='channel' AND EXISTS(
            SELECT 1 FROM public.channels ch JOIN public.channel_memberships cm ON cm.channel_id=ch.id AND cm.user_id=$4
            JOIN public.channel_agents ca ON ca.channel_id=ch.id AND ca.agent_id=a.id
            LEFT JOIN public.deployment_packages cp ON cp.id=ch.package_id
            WHERE ch.id=t.anchor_id AND (ch.package_id IS NULL OR cp.tenant_id=$7))))", " FOR SHARE OF t,r,l,a,p").as_ref(),
        &[&lease.run_id().as_str(),&lease.thread_id().as_str(),&lease.bot_id().as_str(),&lease.actor_id().as_str(),
          &lease.fencing().get(),&deployment.as_str(),&tenant.as_str()])
        .await.map_err(|_|E::Unavailable)?.ok_or(E::Stale)?;
    let channel = (anchor_kind == "channel").then_some(anchor_id.as_str());
    if !lock_v2_agent_package(
        tx,
        lease.bot_id().as_str(),
        tenant.as_str(),
        target.try_get("packaged").map_err(|_| bad())?,
        purpose,
    )
    .await
    .map_err(|_| E::Unavailable)?
        || !lock_v2_anchor_membership(
            tx,
            lease.bot_id().as_str(),
            lease.actor_id().as_str(),
            tenant.as_str(),
            Some(lease.thread_id().as_str()),
            channel,
            purpose,
        )
        .await
        .map_err(|_| E::Unavailable)?
    {
        return Err(E::Stale);
    }
    let connection=tx.query_opt(purpose.statement("SELECT c.name,c.protocol,c.endpoint,c.model FROM public.model_connections c
        WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND c.revision=$5
          AND c.current_secret_id=$6 AND c.protocol=$7 AND c.endpoint=$8 AND c.model=$9
          AND c.enabled AND c.deleted_at IS NULL", " FOR SHARE OF c").as_ref(),
        &[&s.connection_id,&deployment.as_str(),&tenant.as_str(),&lease.actor_id().as_str(),&s.connection_revision,
          &s.secret_id,&s.protocol,&s.endpoint,&s.model]).await.map_err(|_|E::Unavailable)?.ok_or(E::Stale)?;
    tx.query_opt(purpose.statement("SELECT c.connection_id FROM public.custom_model_catalogs c
        WHERE c.connection_id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4
          AND c.model_id=$5 AND c.catalog_revision=$6 AND c.protocol=$7 AND c.endpoint=$8 AND c.model=$9
          AND c.enabled AND NOT c.retired", " FOR SHARE OF c").as_ref(),
        &[&s.connection_id,&deployment.as_str(),&tenant.as_str(),&lease.actor_id().as_str(),&s.model_id,
          &s.catalog_revision,&s.protocol,&s.endpoint,&s.model]).await.map_err(|_|E::Unavailable)?.ok_or(E::Stale)?;
    let secret = tx
        .query_opt(
            purpose
                .statement(
                    "SELECT s.encrypted_value FROM public.model_connection_secrets s
        WHERE s.id=$1 AND s.connection_id=$2 AND s.deployment_id=$3 AND s.tenant_id=$4
          AND s.owner_user_id=$5 AND s.retired_at IS NULL",
                    " FOR SHARE OF s",
                )
                .as_ref(),
            &[
                &s.secret_id,
                &s.connection_id,
                &deployment.as_str(),
                &tenant.as_str(),
                &lease.actor_id().as_str(),
            ],
        )
        .await
        .map_err(|_| E::Unavailable)?
        .ok_or(E::Stale)?;
    let dataset = transaction
        .verify_current_dataset()
        .await
        .map_err(|error| match error {
            crate::model_dataset::ModelDatasetError::InvalidBinding => bad(),
            crate::model_dataset::ModelDatasetError::Unavailable => E::Unavailable,
        })?;
    if dataset.deployment() != deployment
        || dataset.tenant() != tenant
        || s.dataset_id != dataset.dataset_id()
        || s.dataset_binding_schema != dataset.binding_schema()
        || s.dataset_initial_origin != dataset.initial_origin().as_str()
        || s.dataset_binding_created_at != dataset.created_at()
    {
        return Err(bad());
    }
    if !verify_final_v2_authority(
        tx,
        FinalV2Authority {
            deployment: deployment.as_str(),
            tenant: tenant.as_str(),
            actor: lease.actor_id().as_str(),
            auth_generation: s.auth_generation,
            thread: lease.thread_id().as_str(),
            bot: lease.bot_id().as_str(),
            anchor_kind: &anchor_kind,
            anchor_id: &anchor_id,
            fencing: lease.fencing().get(),
            run: Some(lease.run_id().as_str()),
            connection_id: &s.connection_id,
            connection_revision: s.connection_revision,
            secret_id: &s.secret_id,
            protocol: &s.protocol,
            endpoint: &s.endpoint,
            model: &s.model,
            model_id: &s.model_id,
            catalog_revision: s.catalog_revision,
            dataset: &dataset,
        },
    )
    .await
    .map_err(|_| E::Unavailable)?
    {
        return Err(E::Stale);
    }
    let protocol = protocol_from_text(&s.protocol)?;
    let name: String = connection.try_get("name").map_err(|_| bad())?;
    let normalized = normalize_model_configuration(&name, protocol, &s.endpoint, &s.model, true)
        .map_err(|_| bad())?;
    if normalized.endpoint != s.endpoint || normalized.model != s.model {
        return Err(bad());
    }
    let pure_dataset = RunModelDatasetSnapshot::new(
        s.dataset_id,
        s.dataset_binding_schema,
        dataset.initial_origin(),
        s.dataset_binding_created_at,
    )?;
    let snapshot = RunModelV2Snapshot::new(
        selection,
        pure_dataset,
        RunModelCredentialPolicy::CustomFixedSecretRevisionV1,
    )?;
    let binding = RunModelBinding::from_verified_v2_snapshot(
        lease,
        deployment.clone(),
        tenant.clone(),
        openbot_contracts::auth::AuthGeneration::new(generation),
        snapshot,
        s.secret_id.to_string(),
        normalized,
    )?;
    Ok(LoadedSelection {
        binding,
        has_cost_cap: row.try_get("has_cost_cap").map_err(|_| bad())?,
        encrypted_value: zeroize::Zeroizing::new(
            secret.try_get("encrypted_value").map_err(|_| bad())?,
        ),
    })
}
