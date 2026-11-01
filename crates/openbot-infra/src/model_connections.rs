//! Personal model metadata, scoped Vault records and audit share one PostgreSQL transaction.

use crate::{
    repo::audit::{append_event_in_transaction, next_event_coordinates},
    vault::CredentialRecordVault,
};
use async_trait::async_trait;
use openbot_application::model_connections::{
    ModelConnectionAdministration, ModelConnectionError as Error, NormalizedModelConnection,
    normalize_model_configuration,
};
use openbot_contracts::{
    auth::{AuthContext, Role},
    ids::{DeploymentId, TenantId},
    model_connections::*,
    recovery::RecoveryAdmissionLease,
    request_binding::VerifiedHostRequestBinding,
};
use openbot_domain::{
    audit::{
        event::{AuditEvent, AuditEventType},
        payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload},
    },
    vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId},
};
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

const COLUMNS: &str = "c.id,c.name,c.protocol,c.endpoint,c.model,c.enabled,c.revision,c.current_secret_id,c.created_at,c.updated_at,EXISTS(SELECT 1 FROM public.model_connection_secrets s WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.retired_at IS NULL) AS has_credential";

/// Reuse create/update validation in the non-effectful capability inventory.
pub(crate) fn readonly_configuration_valid(
    name: &str,
    protocol: openbot_contracts::model_connections::CustomModelProtocol,
    endpoint: &str,
    model: &str,
    revision: Option<i64>,
) -> bool {
    revision.is_some_and(|value| value > 0)
        && openbot_application::model_connections::normalize_model_configuration(
            name, protocol, endpoint, model, true,
        )
        .is_ok()
}

/// One configured deployment/tenant; no caller can manufacture another scope or owner.
pub struct PostgresModelConnections {
    pool: crate::db::pool::DatabasePool,
    vault: CredentialRecordVault,
    deployment: DeploymentId,
    tenant: TenantId,
    audit_key: SecretBytes,
}

impl PostgresModelConnections {
    /// Bind the existing PG/Vault/audit infrastructure without accessing it at construction.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        vault: CredentialRecordVault,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
    ) -> Result<Self, Error> {
        if deployment.as_str().is_empty()
            || tenant.as_str().is_empty()
            || audit_key.expose().len() < 32
        {
            return Err(Error::InvalidInput {
                field: "model_connection_configuration",
            });
        }
        Ok(Self {
            pool,
            vault,
            deployment,
            tenant,
            audit_key,
        })
    }

    fn scope(&self, auth: &AuthContext) -> Result<(), Error> {
        if auth.deployment() != &self.deployment
            || auth.tenant() != &self.tenant
            || !(auth.has_role(Role::User) || auth.has_role(Role::Admin))
        {
            return Err(Error::NotVisible);
        }
        Ok(())
    }

    async fn row(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        id: Uuid,
        lock: bool,
    ) -> Result<Row, Error> {
        let lock = if lock { " FOR UPDATE OF c" } else { "" };
        tx.query_opt(&format!("SELECT {COLUMNS} FROM public.model_connections c WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND c.deleted_at IS NULL{lock}"),
            &[&id, &self.deployment.as_str(), &self.tenant.as_str(), &auth.actor().as_str()])
            .await.map_err(unavailable)?.ok_or(Error::NotVisible)
    }

    fn principal(id: Uuid) -> SecretPrincipal {
        SecretPrincipal::Service(ServiceId::new(id.to_string()))
    }

    async fn new_secret(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        connection: Uuid,
        input: &ModelApiKey,
        now: OffsetDateTime,
    ) -> Result<Uuid, Error> {
        let id = Uuid::now_v7();
        let secret = SecretBytes::new(input.expose().as_bytes().to_vec());
        let owner = SecretPrincipal::Actor(auth.actor().clone());
        let encrypted = self
            .vault
            .seal(
                &id,
                SecretKind::Model,
                owner.clone(),
                Self::principal(connection),
                &secret,
            )
            .map_err(|_| Error::Corrupt)?;
        let row = tx.query_one("INSERT INTO public.model_connection_secrets(id,connection_id,deployment_id,tenant_id,owner_user_id,encrypted_value,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING encrypted_value",
            &[&id,&connection,&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str(),&encrypted,&now]).await.map_err(unavailable)?;
        let stored: String = row.try_get(0).map_err(|_| Error::Corrupt)?;
        let opened = self
            .vault
            .open(
                &id,
                SecretKind::Model,
                owner,
                Self::principal(connection),
                &stored,
            )
            .map_err(|_| Error::Corrupt)?;
        // This new table has no legacy credentials: accepting v1 would discard the owner AAD.
        if opened.needs_migration() {
            return Err(Error::Corrupt);
        }
        let verified = opened.into_secret();
        if !secret.ct_eq(&verified) {
            return Err(Error::Corrupt);
        }
        Ok(id)
    }

    async fn check_current_secret(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        connection: Uuid,
        secret: Uuid,
    ) -> Result<(), Error> {
        let row = tx.query_opt("SELECT encrypted_value FROM public.model_connection_secrets WHERE id=$1 AND connection_id=$2 AND deployment_id=$3 AND tenant_id=$4 AND owner_user_id=$5 AND retired_at IS NULL FOR UPDATE",
            &[&secret,&connection,&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str()]).await.map_err(unavailable)?.ok_or(Error::Corrupt)?;
        let encrypted: String = row.try_get(0).map_err(|_| Error::Corrupt)?;
        let opened = self
            .vault
            .open(
                &secret,
                SecretKind::Model,
                SecretPrincipal::Actor(auth.actor().clone()),
                Self::principal(connection),
                &encrypted,
            )
            .map_err(|_| Error::Corrupt)?;
        if opened.needs_migration() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    async fn audit(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        connection: Uuid,
        change: &'static str,
    ) -> Result<(), Error> {
        let (id, created_at) = next_event_coordinates(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(auth.actor().clone()),
            event_type: AuditEventType::parse("configuration.changed").ok_or(Error::Corrupt)?,
            target_kind: AuditLabel::new("model_connection"),
            target_id: Some(
                AuditIdentifier::new(connection.to_string()).map_err(|_| Error::Corrupt)?,
            ),
            payload: AuditPayload::from_facts(vec![AuditFact::ConfigurationChange(
                AuditLabel::new(change),
            )])
            .map_err(|_| Error::Corrupt)?,
            created_at,
        };
        append_event_in_transaction(tx, &event, self.audit_key.expose())
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}

impl std::fmt::Debug for PostgresModelConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresModelConnections")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ModelConnectionAdministration for PostgresModelConnections {
    async fn list(
        &self,
        auth: &AuthContext,
        request: &ModelConnectionPageRequest,
    ) -> Result<ModelConnectionPage, Error> {
        self.scope(auth)?;
        let cursor = request.cursor.as_deref().map(parse_id).transpose()?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        lock_actor(&tx, auth).await?;
        let limit = (MODEL_CONNECTION_PAGE_SIZE + 1) as i64;
        let rows = tx.query(&format!("SELECT {COLUMNS} FROM public.model_connections c WHERE c.deployment_id=$1 AND c.tenant_id=$2 AND c.owner_user_id=$3 AND c.deleted_at IS NULL AND ($4::uuid IS NULL OR c.id>$4) ORDER BY c.id LIMIT $5"),
            &[&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str(),&cursor,&limit]).await.map_err(unavailable)?;
        let connections: Vec<_> = rows
            .iter()
            .take(MODEL_CONNECTION_PAGE_SIZE)
            .map(project)
            .collect::<Result<_, _>>()?;
        let next_cursor = if rows.len() > MODEL_CONNECTION_PAGE_SIZE {
            connections.last().map(|r| r.id.clone())
        } else {
            None
        };
        tx.commit().await.map_err(unavailable)?;
        Ok(ModelConnectionPage {
            connections,
            next_cursor,
        })
    }

    async fn get(&self, auth: &AuthContext, id: &str) -> Result<ModelConnection, Error> {
        self.scope(auth)?;
        let id = parse_id(id)?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        lock_actor(&tx, auth).await?;
        let result = project(&self.row(&tx, auth, id, false).await?)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(result)
    }

    async fn create(
        &self,
        auth: &AuthContext,
        input: &CreateModelConnection,
    ) -> Result<ModelConnection, Error> {
        self.scope(auth)?;
        let config = normalize_model_configuration(
            &input.name,
            input.protocol,
            &input.endpoint,
            &input.model,
            input.enabled,
        )?;
        let (binding, admission, deadline) = admitted(auth).await?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        lock_actor(&tx, auth).await?;
        let id = Uuid::now_v7();
        let now = now(&tx).await?;
        let secret = self.new_secret(&tx, auth, id, &input.api_key, now).await?;
        tx.execute("INSERT INTO public.model_connections(id,deployment_id,tenant_id,owner_user_id,name,protocol,endpoint,model,enabled,revision,current_secret_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$11)",
            &[&id,&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str(),&config.name,&config.protocol.as_str(),&config.endpoint,&config.model,&config.enabled,&secret,&now]).await.map_err(unavailable)?;
        self.audit(&tx, auth, id, "model_connection_created")
            .await?;
        let result = project(&self.row(&tx, auth, id, false).await?)?;
        current(&admission, binding, auth, deadline)?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(result)
    }

    async fn update(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &UpdateModelConnection,
    ) -> Result<ModelConnection, Error> {
        self.scope(auth)?;
        let id = parse_id(id)?;
        revision(input.expected_revision)?;
        let config = normalize_model_configuration(
            &input.name,
            input.protocol,
            &input.endpoint,
            &input.model,
            input.enabled,
        )?;
        let (binding, admission, deadline) = admitted(auth).await?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        lock_actor(&tx, auth).await?;
        let old = self.row(&tx, auth, id, true).await?;
        let previous = project(&old)?;
        if previous.revision != input.expected_revision {
            return Err(stale_snapshot(&previous)?);
        }
        if (previous.protocol != config.protocol || previous.endpoint != config.endpoint)
            && input.api_key.is_none()
        {
            return Err(Error::InvalidInput { field: "apiKey" });
        }
        let old_secret: Uuid = old
            .try_get("current_secret_id")
            .map_err(|_| Error::Corrupt)?;
        // The restored logical connection, not its rotating secret row, is the source.
        crate::restore_reconfirmation::require_confirmed_before(
            &*tx,
            crate::restore_reconfirmation::RequirementSource {
                cohort: admission.restore_cohort(),
                kind: crate::restore_reconfirmation::RequirementKind::ModelSecret,
                source_ref: &id.to_string(),
            },
            deadline,
        )
        .await
        .map_err(|error| match error {
            crate::restore_reconfirmation::RestoreReconfirmationError::NotConfirmed => {
                Error::NotVisible
            }
            crate::restore_reconfirmation::RestoreReconfirmationError::Unavailable => {
                Error::Unavailable
            }
        })?;
        current(&admission, binding, auth, deadline)?;
        self.check_current_secret(&tx, auth, id, old_secret).await?;
        let now = now(&tx).await?;
        let secret = match &input.api_key {
            Some(key) => self.new_secret(&tx, auth, id, key, now).await?,
            None => old_secret,
        };
        let revision = previous.revision.checked_add(1).ok_or(Error::Conflict)?;
        tx.execute("UPDATE public.model_connections SET name=$2,protocol=$3,endpoint=$4,model=$5,enabled=$6,revision=$7,current_secret_id=$8,updated_at=$9 WHERE id=$1",
            &[&id,&config.name,&config.protocol.as_str(),&config.endpoint,&config.model,&config.enabled,&revision,&secret,&now]).await.map_err(unavailable)?;
        if secret != old_secret {
            tx.execute("UPDATE public.model_connection_secrets SET retired_at=$2 WHERE id=$1 AND retired_at IS NULL", &[&old_secret,&now]).await.map_err(unavailable)?;
        }
        let change = if secret != old_secret {
            "model_connection_key_rotated"
        } else {
            "model_connection_updated"
        };
        self.audit(&tx, auth, id, change).await?;
        let result = project(&self.row(&tx, auth, id, false).await?)?;
        current(&admission, binding, auth, deadline)?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(result)
    }

    async fn delete(
        &self,
        auth: &AuthContext,
        id: &str,
        input: &DeleteModelConnection,
    ) -> Result<ModelConnectionDeleted, Error> {
        self.scope(auth)?;
        let id = parse_id(id)?;
        revision(input.expected_revision)?;
        let (binding, admission, deadline) = admitted(auth).await?;
        let mut client = self.pool.get().await.map_err(|_| Error::Unavailable)?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(unavailable)?;
        lock_actor(&tx, auth).await?;
        let row = self.row(&tx, auth, id, true).await?;
        let old_revision: i64 = row.try_get("revision").map_err(|_| Error::Corrupt)?;
        if old_revision != input.expected_revision {
            return Err(stale_snapshot(&project(&row)?)?);
        }
        let revision = old_revision.checked_add(1).ok_or(Error::Conflict)?;
        let now = now(&tx).await?;
        tx.execute("UPDATE public.model_connections SET enabled=false,deleted_at=$2,updated_at=$2,revision=$3 WHERE id=$1", &[&id,&now,&revision]).await.map_err(unavailable)?;
        tx.execute("UPDATE public.model_connection_secrets SET retired_at=coalesce(retired_at,$2) WHERE connection_id=$1", &[&id,&now]).await.map_err(unavailable)?;
        self.audit(&tx, auth, id, "model_connection_deleted")
            .await?;
        current(&admission, binding, auth, deadline)?;
        tx.commit().await.map_err(|_| Error::CommitUnknown)?;
        Ok(ModelConnectionDeleted {
            id: id.to_string(),
            revision,
            deleted_at: now,
        })
    }
}

/// Each writer takes its one deadline at entry (no per-step bound,
/// so the 5 s precedent) and borrows the original request's recovery admission.
async fn admitted(
    auth: &AuthContext,
) -> Result<
    (
        &VerifiedHostRequestBinding,
        RecoveryAdmissionLease<'_>,
        std::time::Instant,
    ),
    Error,
> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let binding = auth.request_binding().ok_or(Error::Unavailable)?;
    let admission = binding
        .borrow_recovery_admission_before(auth, deadline)
        .await
        .map_err(|_| Error::Unavailable)?;
    Ok((binding, admission, deadline))
}

/// The same admission, rechecked before a Vault-open and before COMMIT.
fn current(
    admission: &RecoveryAdmissionLease<'_>,
    binding: &VerifiedHostRequestBinding,
    auth: &AuthContext,
    deadline: std::time::Instant,
) -> Result<(), Error> {
    admission
        .verify_current_before(binding, auth, deadline)
        .map_err(|_| Error::Unavailable)
}

async fn lock_actor(tx: &Transaction<'_>, auth: &AuthContext) -> Result<(), Error> {
    let generation = i64::try_from(auth.auth_generation().get()).map_err(|_| Error::NotVisible)?;
    let row = tx.query_opt("SELECT u.id FROM public.users u WHERE u.id=$1 AND coalesce(u.auth_generation,0)=$2 AND EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=u.id AND r.role IN ('user','admin')) AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)) FOR SHARE OF u", &[&auth.actor().as_str(),&generation]).await.map_err(unavailable)?;
    row.map(|_| ()).ok_or(Error::NotVisible)
}

fn stale_snapshot(row: &ModelConnection) -> Result<Error, Error> {
    openbot_contracts::revision::RevisionSnapshot::from_public(row.revision, row.updated_at, row)
        .map(Error::StaleSnapshot)
        .map_err(|_| Error::Corrupt)
}
fn parse_id(value: &str) -> Result<Uuid, Error> {
    if value.len() != 36 {
        return Err(Error::InvalidInput {
            field: "connection_id",
        });
    }
    Uuid::parse_str(value).map_err(|_| Error::InvalidInput {
        field: "connection_id",
    })
}
fn revision(value: i64) -> Result<(), Error> {
    if value <= 0 {
        Err(Error::InvalidInput {
            field: "expectedRevision",
        })
    } else {
        Ok(())
    }
}
async fn now(tx: &Transaction<'_>) -> Result<OffsetDateTime, Error> {
    tx.query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(unavailable)?
        .try_get(0)
        .map_err(|_| Error::Corrupt)
}
fn unavailable(_: tokio_postgres::Error) -> Error {
    Error::Unavailable
}

fn project(row: &Row) -> Result<ModelConnection, Error> {
    fn get<T: for<'a> tokio_postgres::types::FromSql<'a>>(
        row: &Row,
        field: &str,
    ) -> Result<T, Error> {
        row.try_get(field).map_err(|_| Error::Corrupt)
    }
    let protocol = match get::<String>(row, "protocol")?.as_str() {
        "openai_chat_completions" => CustomModelProtocol::OpenaiChatCompletions,
        "openai_responses" => CustomModelProtocol::OpenaiResponses,
        "anthropic_messages" => CustomModelProtocol::AnthropicMessages,
        _ => return Err(Error::Corrupt),
    };
    let stored_endpoint: String = get(row, "endpoint")?;
    let config: NormalizedModelConnection = normalize_model_configuration(
        &get::<String>(row, "name")?,
        protocol,
        &stored_endpoint,
        &get::<String>(row, "model")?,
        get(row, "enabled")?,
    )
    .map_err(|_| Error::Corrupt)?;
    if stored_endpoint != config.endpoint {
        return Err(Error::Corrupt);
    }
    let revision: i64 = get(row, "revision")?;
    if revision <= 0 {
        return Err(Error::Corrupt);
    }
    Ok(ModelConnection {
        id: get::<Uuid>(row, "id")?.to_string(),
        source: ModelConnectionSource::Custom,
        name: config.name,
        protocol,
        endpoint: config.endpoint,
        model: config.model,
        enabled: config.enabled,
        revision,
        has_credential: get(row, "has_credential")?,
        created_at: get(row, "created_at")?,
        updated_at: get(row, "updated_at")?,
    })
}
