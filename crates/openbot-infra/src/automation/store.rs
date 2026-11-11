//! Same-PG owner management and durable manual acceptance.

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openbot_application::automation::{
    AutomationAcceptance, AutomationCreation, AutomationDefinitions, AutomationListRequest,
    AutomationPageRequest, AutomationUpdate,
};
use openbot_contracts::{
    auth::AuthContext,
    automation::*,
    command::ThreadRunAnchor,
    error::AppError,
    ids::{ActorId, DeploymentId, RunId, TenantId, ThreadId},
};
use openbot_domain::{
    audit::{
        event::{AuditEvent, AuditEventType},
        payload::{AuditFact, AuditIdentifier, AuditLabel, AuditPayload},
    },
    automation::AutomationConfig,
    vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio_postgres::{Row, Transaction, types::FromSql};
use uuid::Uuid;

/// The original scoped Pool is the sole source of definitions, grants and accepted work.
#[derive(Clone, Debug)]
pub struct PostgresAutomations {
    pub(crate) pool: crate::db::pool::DatabasePool,
    pub(crate) deployment: DeploymentId,
    pub(crate) tenant: TenantId,
    audit_key: Arc<SecretBytes>,
    /// Existing Vault holding one credentials row per receiver key revision.
    pub(crate) vault: crate::vault::CredentialRecordVault,
    /// Per-receiver process token buckets: 10 per second, burst 20.
    pub(crate) rate:
        Arc<std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, f64)>>>,
}

impl PostgresAutomations {
    /// Construct only at a host that owns Server automation; Desktop leaves the port absent.
    pub fn new(
        pool: crate::db::pool::DatabasePool,
        deployment: DeploymentId,
        tenant: TenantId,
        audit_key: SecretBytes,
        vault: crate::vault::CredentialRecordVault,
    ) -> Result<Self, AppError> {
        if audit_key.is_empty() {
            return Err(unavailable());
        }
        Ok(Self {
            pool,
            deployment,
            tenant,
            audit_key: Arc::new(audit_key),
            vault,
            rate: Arc::default(),
        })
    }

    async fn prepare(&self, tx: &Transaction<'_>, auth: &AuthContext) -> Result<(), AppError> {
        if auth.deployment() != &self.deployment || auth.tenant() != &self.tenant {
            return Err(AppError::NotVisible);
        }
        tx.batch_execute("SET LOCAL lock_timeout='4s'; SET LOCAL statement_timeout='4s'")
            .await
            .map_err(|_| unavailable())?;
        crate::thread_history_writer::CurrentWriterSchema::observe(tx)
            .await
            .map_err(|_| unavailable())?;
        crate::thread_origin::current_native_actor(
            tx,
            auth.actor().as_str(),
            auth.auth_generation(),
        )
        .await
        .map_err(|_| unavailable())?
        .ok_or(AppError::NotVisible)?;
        Ok(())
    }

    async fn definition_row(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        id: &AutomationId,
        lock: bool,
    ) -> Result<Row, AppError> {
        let suffix = if lock { " FOR UPDATE OF d" } else { "" };
        tx.query_opt(&format!("SELECT d.*,r.config_snapshot,r.delegation_revision
            FROM openbot_internal.automation_definitions d
            JOIN openbot_internal.automation_definition_revisions r
              ON (r.deployment_id,r.tenant_id,r.automation_id,r.revision)=
                 (d.deployment_id,d.tenant_id,d.automation_id,d.current_revision)
            WHERE d.deployment_id=$1 AND d.tenant_id=$2 AND d.owner_id=$3 AND d.automation_id=$4{suffix}"),
            &[&self.deployment.as_str(), &self.tenant.as_str(), &auth.actor().as_str(), &id.as_str()])
            .await.map_err(|_| unavailable())?.ok_or(AppError::NotVisible)
    }

    async fn projection(
        &self,
        tx: &Transaction<'_>,
        row: &Row,
    ) -> Result<AutomationDefinition, AppError> {
        let id: String = column(row, "automation_id")?;
        let owner: String = column(row, "owner_id")?;
        let grant_revision: Option<i64> = column(row, "delegation_revision")?;
        let grant = if let Some(revision) = grant_revision {
            let grant = tx.query_one("SELECT g.expires_at,
                g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>statement_timestamp())
                AND g.granted_auth_generation=COALESCE(u.auth_generation,0)
                AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email)) AS valid
                FROM openbot_internal.automation_delegations g JOIN public.users u ON u.id=g.owner_id
                WHERE g.deployment_id=$1 AND g.tenant_id=$2 AND g.automation_id=$3 AND g.delegation_revision=$4",
                &[&self.deployment.as_str(), &self.tenant.as_str(), &id, &revision])
                .await.map_err(|_| unavailable())?;
            AutomationGrantProjection {
                revision: Some(revision.try_into()?),
                valid: column(&grant, "valid")?,
                expires_at: column(&grant, "expires_at")?,
            }
        } else {
            AutomationGrantProjection {
                revision: None,
                valid: false,
                expires_at: None,
            }
        };
        let latest = tx.query_opt("SELECT occurrence_id,run_id FROM openbot_internal.automation_occurrences
            WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 ORDER BY accepted_at DESC,occurrence_id DESC LIMIT 1",
            &[&self.deployment.as_str(), &self.tenant.as_str(), &id]).await.map_err(|_| unavailable())?;
        let timezone = tx.query_opt("SELECT timezone_id,tzdb_version,unavailable_reason FROM openbot_internal.automation_cron_progress
            WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3",
            &[&self.deployment.as_str(), &self.tenant.as_str(), &id]).await.map_err(|_| unavailable())?
            .map(|row| Ok::<_, AppError>(AutomationTimezoneSnapshot {
                timezone_id: column(&row, "timezone_id")?, tzdb_version: column(&row, "tzdb_version")?,
                unavailable_reason: column::<Option<String>>(&row, "unavailable_reason")?.map(string_value).transpose()?,
            })).transpose()?;
        Ok(AutomationDefinition {
            id: id.clone().try_into()?,
            revision: column::<i64>(row, "current_revision")?.try_into()?,
            state: string_value(column(row, "state")?)?,
            config: stored(column(row, "config_snapshot")?)?,
            thread_id: ThreadId::new(column::<String>(row, "thread_id")?),
            grant,
            budget: crate::automation_budget::projection(
                tx,
                &self.deployment,
                &self.tenant,
                &owner,
                &id,
            )
            .await?,
            unpriced: true,
            latest_occurrence_id: latest
                .as_ref()
                .map(|r| column::<String>(r, "occurrence_id"))
                .transpose()?
                .map(AutomationReceiptId::try_from)
                .transpose()?,
            latest_run_id: latest
                .as_ref()
                .map(|r| column::<Option<String>>(r, "run_id"))
                .transpose()?
                .flatten()
                .map(RunId::new),
            timezone,
            created_at: column(row, "created_at")?,
            updated_at: column(row, "updated_at")?,
        })
    }

    pub(crate) async fn audit(
        &self,
        tx: &Transaction<'_>,
        actor: Option<&ActorId>,
        id: &AutomationId,
        action: &'static str,
    ) -> Result<(), AppError> {
        let (event_id, created_at) = crate::repo::audit::next_event_coordinates(tx)
            .await
            .map_err(|_| unavailable())?;
        let event = AuditEvent {
            id: event_id,
            actor: actor.cloned(),
            event_type: AuditEventType::parse("configuration.changed").ok_or_else(unavailable)?,
            target_kind: AuditLabel::new("automation"),
            target_id: Some(AuditIdentifier::new(id.as_str()).map_err(|_| unavailable())?),
            payload: AuditPayload::from_facts([AuditFact::ConfigurationChange(AuditLabel::new(
                action,
            ))])
            .map_err(|_| unavailable())?,
            created_at,
        };
        crate::repo::audit::append_event_in_transaction(tx, &event, self.audit_key.expose())
            .await
            .map_err(|_| unavailable())?;
        Ok(())
    }
}

#[async_trait]
impl AutomationDefinitions for PostgresAutomations {
    async fn create(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        config: AutomationConfig,
    ) -> Result<AutomationCreation, AppError> {
        super::time::validate_draft(&config)?;
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('automation:'||$1::text,0))",
            &[&id.as_str()],
        )
        .await
        .map_err(|_| unavailable())?;
        if let Some(existing) = tx.query_opt("SELECT deployment_id,tenant_id,owner_id FROM openbot_internal.automation_definitions WHERE automation_id=$1 FOR UPDATE", &[&id.as_str()]).await.map_err(|_| unavailable())? {
            if column::<String>(&existing,"deployment_id")? != self.deployment.as_str()
                || column::<String>(&existing,"tenant_id")? != self.tenant.as_str()
                || column::<String>(&existing,"owner_id")? != auth.actor().as_str() { return Err(AppError::NotVisible); }
            let original: Value = tx.query_one("SELECT config_snapshot FROM openbot_internal.automation_definition_revisions WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND revision=1", &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_| unavailable())?.get(0);
            let original: AutomationConfigV1 = stored(original)?;
            if original != *config.wire() { return Err(AppError::AutomationOperationConflict); }
            let row = self.definition_row(&tx,auth,&id,false).await?;
            let result = self.projection(&tx,&row).await?;
            tx.rollback().await.map_err(|_| unavailable())?;
            return Ok(AutomationCreation::Replayed(result));
        }
        let facts = crate::delegation::owner_snapshot(
            &tx,
            &self.deployment,
            &self.tenant,
            auth.actor(),
            &config.wire().bot_id,
        )
        .await?;
        if facts.revoked || !facts.bot_visible || facts.auth_generation != auth.auth_generation() {
            return Err(AppError::NotVisible);
        }
        let thread =
            crate::thread_id::mint_thread_id(&self.deployment).map_err(|_| unavailable())?;
        let now: OffsetDateTime = tx
            .query_one("SELECT statement_timestamp()", &[])
            .await
            .map_err(|_| unavailable())?
            .get(0);
        crate::thread_directory::insert_native_thread(
            &tx,
            crate::thread_directory::NewNativeThread {
                deployment: &self.deployment,
                tenant: &self.tenant,
                actor: auth.actor(),
                auth_generation: auth.auth_generation(),
                thread_id: &thread,
                bot_id: &config.wire().bot_id,
                anchor: &ThreadRunAnchor::DirectBot,
                now,
            },
        )
        .await
        .map_err(|e| e.into_app_error())?;
        tx.execute("INSERT INTO openbot_internal.automation_definitions(automation_id,deployment_id,tenant_id,owner_id,bot_id,thread_id,current_revision,state)
            VALUES($1,$2,$3,$4,$5,$6,1,'paused')", &[&id.as_str(),&self.deployment.as_str(),&self.tenant.as_str(),&auth.actor().as_str(),&config.wire().bot_id.as_str(),&thread.as_str()]).await.map_err(|_| unavailable())?;
        let snapshot = serde_json::to_value(config.wire()).map_err(|_| unavailable())?;
        tx.execute("INSERT INTO openbot_internal.automation_definition_revisions(deployment_id,tenant_id,automation_id,revision,config_snapshot) VALUES($1,$2,$3,1,$4)",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&snapshot]).await.map_err(|_| unavailable())?;
        crate::automation_budget::replace_automation_policy(
            &tx,
            &self.deployment,
            &self.tenant,
            &id,
            1,
            &config.wire().budget,
        )
        .await?;
        self.audit(&tx, Some(auth.actor()), &id, "automation_created")
            .await?;
        let row = self.definition_row(&tx, auth, &id, false).await?;
        let result = self.projection(&tx, &row).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AutomationCreation::Created(result))
    }

    async fn get(
        &self,
        auth: &AuthContext,
        id: AutomationId,
    ) -> Result<AutomationDefinition, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let row = self.definition_row(&tx, auth, &id, false).await?;
        let result = self.projection(&tx, &row).await?;
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(result)
    }

    async fn list(
        &self,
        auth: &AuthContext,
        input: AutomationListRequest,
    ) -> Result<AutomationDefinitionPage, AppError> {
        let namespace = format!("definitions:{}", input.status.as_str());
        let cursor = decode_cursor(input.page.cursor(), auth, &namespace)?;
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let (at, id) = cursor.unzip();
        let rows = tx
            .query(
                "SELECT automation_id,updated_at FROM openbot_internal.automation_definitions
            WHERE deployment_id=$1 AND tenant_id=$2 AND owner_id=$3
              AND ($4='all' OR ($4='active' AND state IN ('paused','enabled')) OR state=$4)
              AND ($5::timestamptz IS NULL OR (updated_at,automation_id)<($5,$6))
            ORDER BY updated_at DESC,automation_id DESC LIMIT $7",
                &[
                    &self.deployment.as_str(),
                    &self.tenant.as_str(),
                    &auth.actor().as_str(),
                    &input.status.as_str(),
                    &at,
                    &id,
                    &(i64::from(input.page.limit()) + 1),
                ],
            )
            .await
            .map_err(|_| unavailable())?;
        let next_cursor = next_cursor(
            &rows,
            input.page.limit(),
            auth,
            &namespace,
            "updated_at",
            "automation_id",
        )?;
        let mut items = Vec::new();
        for row in rows.iter().take(input.page.limit() as usize) {
            let id = AutomationId::try_from(column::<String>(row, "automation_id")?)?;
            let definition = self.definition_row(&tx, auth, &id, false).await?;
            items.push(self.projection(&tx, &definition).await?);
        }
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(AutomationDefinitionPage { items, next_cursor })
    }

    async fn update(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        input: AutomationUpdate,
    ) -> Result<AutomationDefinition, AppError> {
        self.mutate(auth, id, input, false).await
    }
    async fn tombstone(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        revision: AutomationRevision,
    ) -> Result<AutomationDefinition, AppError> {
        self.mutate(
            auth,
            id,
            AutomationUpdate::Revoke {
                expected_revision: revision,
            },
            true,
        )
        .await
    }

    async fn trigger(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        input: TriggerAutomationDefinition,
    ) -> Result<AutomationAcceptance, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let row = self.definition_row(&tx, auth, &id, true).await?;
        if column::<String>(&row, "state")? != "enabled" {
            return Err(AppError::AutomationNotAccepting);
        }
        valid_grant(&tx, &self.deployment, &self.tenant, &row).await?;
        if let Some(previous)=tx.query_opt("SELECT occurrence_id,intent_snapshot FROM openbot_internal.automation_occurrences WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND manual_operation_id=$4",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&input.operation_id.as_str()]).await.map_err(|_|unavailable())?{
            let intent:Value=column(&previous,"intent_snapshot")?;
            if intent.get("operationId").and_then(Value::as_str)!=Some(input.operation_id.as_str()) || intent.get("expectedRevision").and_then(Value::as_i64)!=Some(input.expected_revision.get()) {return Err(AppError::AutomationOperationConflict);}
            let receipt=read_receipt(&tx,&self.deployment,&self.tenant,auth.actor().as_str(),column::<String>(&previous,"occurrence_id")?.as_str()).await?;
            tx.rollback().await.map_err(|_|unavailable())?;
            return Ok(AutomationAcceptance::Replayed(receipt));
        }
        if column::<i64>(&row, "current_revision")? != input.expected_revision.get() {
            return Err(AppError::AutomationRevisionConflict);
        }
        if column::<i64>(&row, "pending_count")? >= 100 {
            return Err(AppError::AutomationCapacityExceeded);
        }
        let workspace=tx.query_one("SELECT pending_count FROM openbot_internal.automation_workspace_capacity WHERE deployment_id=$1 AND tenant_id=$2",&[&self.deployment.as_str(),&self.tenant.as_str()]).await.map_err(|_|unavailable())?;
        if column::<i64>(&workspace, "pending_count")? >= 1000 {
            return Err(AppError::AutomationCapacityExceeded);
        }
        let occurrence = format!("aocc:{}", Uuid::now_v7());
        let generation = i64::try_from(auth.auth_generation().get()).map_err(|_| unavailable())?;
        let intent = json!({"schemaVersion":1,"kind":"manual","operationId":input.operation_id,"expectedRevision":input.expected_revision,"actorId":auth.actor(),"authGeneration":generation});
        tx.execute("INSERT INTO openbot_internal.automation_occurrences(occurrence_id,deployment_id,tenant_id,automation_id,definition_revision,trigger_kind,manual_operation_id,intent_snapshot,state) VALUES($1,$2,$3,$4,$5,'manual',$6,$7,'pending')",
            &[&occurrence,&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&input.expected_revision.get(),&input.operation_id.as_str(),&intent]).await.map_err(|_|unavailable())?;
        adjust_pending(&tx, &self.deployment, &self.tenant, &id, 1).await?;
        tx.execute("INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) VALUES($1,'automation',$2,0,'automation.dispatch','internal',$3)",
            &[&format!("{occurrence}:automation_dispatch"),&occurrence,&json!({"automationId":id,"occurrenceId":occurrence})]).await.map_err(|_|unavailable())?;
        tx.query_one("SELECT pg_notify('openbot_automation',$1)", &[&id.as_str()])
            .await
            .map_err(|_| unavailable())?;
        self.audit(&tx, Some(auth.actor()), &id, "automation_manual_accepted")
            .await?;
        let receipt = read_receipt(
            &tx,
            &self.deployment,
            &self.tenant,
            auth.actor().as_str(),
            &occurrence,
        )
        .await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AutomationAcceptance::Accepted(receipt))
    }

    async fn receipt(
        &self,
        auth: &AuthContext,
        id: AutomationReceiptId,
    ) -> Result<AutomationReceipt, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let receipt = read_receipt(
            &tx,
            &self.deployment,
            &self.tenant,
            auth.actor().as_str(),
            id.as_str(),
        )
        .await?;
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(receipt)
    }

    async fn occurrences(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        page: AutomationPageRequest,
    ) -> Result<AutomationOccurrencePage, AppError> {
        let namespace = format!("occurrences:{}", id.as_str());
        let cursor = decode_cursor(page.cursor(), auth, &namespace)?;
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        self.definition_row(&tx, auth, &id, false).await?;
        let (at, position) = cursor.unzip();
        let rows=tx.query("SELECT occurrence_id,accepted_at FROM openbot_internal.automation_occurrences WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND ($4::timestamptz IS NULL OR (accepted_at,occurrence_id)<($4,$5)) ORDER BY accepted_at DESC,occurrence_id DESC LIMIT $6",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&at,&position,&(i64::from(page.limit())+1)]).await.map_err(|_|unavailable())?;
        let next_cursor = next_cursor(
            &rows,
            page.limit(),
            auth,
            &namespace,
            "accepted_at",
            "occurrence_id",
        )?;
        let mut items = Vec::new();
        for row in rows.iter().take(page.limit() as usize) {
            let receipt = read_receipt(
                &tx,
                &self.deployment,
                &self.tenant,
                auth.actor().as_str(),
                &column::<String>(row, "occurrence_id")?,
            )
            .await?;
            items.push(receipt.occurrence.ok_or_else(unavailable)?);
        }
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(AutomationOccurrencePage { items, next_cursor })
    }

    async fn deliveries(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        page: AutomationPageRequest,
    ) -> Result<AutomationDeliveryPage, AppError> {
        let namespace = format!("deliveries:{}", id.as_str());
        let cursor = decode_cursor(page.cursor(), auth, &namespace)?;
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        self.definition_row(&tx, auth, &id, false).await?;
        let (at, position) = cursor.unzip();
        let rows=tx.query("SELECT receipt_id,received_at FROM openbot_internal.automation_deliveries WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND ($4::timestamptz IS NULL OR (received_at,receipt_id)<($4,$5)) ORDER BY received_at DESC,receipt_id DESC LIMIT $6",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&at,&position,&(i64::from(page.limit())+1)]).await.map_err(|_|unavailable())?;
        let next_cursor = next_cursor(
            &rows,
            page.limit(),
            auth,
            &namespace,
            "received_at",
            "receipt_id",
        )?;
        let mut items = Vec::new();
        for row in rows.iter().take(page.limit() as usize) {
            items.push(
                read_receipt(
                    &tx,
                    &self.deployment,
                    &self.tenant,
                    auth.actor().as_str(),
                    &column::<String>(row, "receipt_id")?,
                )
                .await?,
            );
        }
        let mut receivers = Vec::new();
        for row in tx.query("SELECT receiver_id FROM openbot_internal.automation_receivers WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 ORDER BY created_at,receiver_id",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())? {
            receivers.push(read_receiver(&tx, &self.deployment, &self.tenant, &column::<String>(&row, "receiver_id")?).await?);
        }
        tx.rollback().await.map_err(|_| unavailable())?;
        Ok(AutomationDeliveryPage {
            items,
            next_cursor,
            receivers,
        })
    }

    async fn create_receiver(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        receiver: AutomationReceiverId,
        expected_revision: AutomationRevision,
        filter: AutomationEventFilter,
    ) -> Result<AutomationReceiverSecret, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let row = self.definition_row(&tx, auth, &id, true).await?;
        if column::<i64>(&row, "current_revision")? != expected_revision.get() {
            return Err(AppError::AutomationRevisionConflict);
        }
        if column::<String>(&row, "state")? == "tombstoned" {
            return Err(AppError::AutomationNotAccepting);
        }
        let config: AutomationConfigV1 = stored(column(&row, "config_snapshot")?)?;
        if !matches!(config.trigger, AutomationTrigger::Event {}) {
            return Err(AppError::MalformedPayload { field: "source" });
        }
        let (credential, sender_key) = self.insert_sender_key(&tx, auth.actor(), &receiver).await?;
        let principal = serde_json::to_value(AutomationSourcePrincipal::SenderKey {
            receiver_id: receiver.clone(),
        })
        .map_err(|_| unavailable())?;
        let filter = serde_json::to_value(&filter).map_err(|_| unavailable())?;
        // Receiver namespaces are permanent and never reused, by this or any other owner.
        let inserted = tx.execute("INSERT INTO openbot_internal.automation_receivers(receiver_id,deployment_id,tenant_id,automation_id,adapter,source_principal,event_filter,current_key_revision,vault_record_ref)
            VALUES($1,$2,$3,$4,'sender_key',$5,$6,1,$7) ON CONFLICT (receiver_id) DO NOTHING",
            &[&receiver.as_str(),&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&principal,&filter,&credential.to_string()]).await.map_err(|_|unavailable())?;
        if inserted != 1 {
            return Err(AppError::AutomationOperationConflict);
        }
        self.audit(&tx, Some(auth.actor()), &id, "automation_receiver_created")
            .await?;
        let receiver =
            read_receiver(&tx, &self.deployment, &self.tenant, receiver.as_str()).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AutomationReceiverSecret {
            receiver,
            sender_key,
        })
    }

    async fn rotate_receiver_key(
        &self,
        auth: &AuthContext,
        receiver: AutomationReceiverId,
        expected_key_revision: AutomationRevision,
    ) -> Result<AutomationReceiverSecret, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let row = self.owned_receiver(&tx, auth, &receiver).await?;
        if column::<Option<OffsetDateTime>>(&row, "revoked_at")?.is_some()
            || column::<i64>(&row, "current_key_revision")? != expected_key_revision.get()
        {
            return Err(AppError::AutomationKeyRevisionConflict);
        }
        let (credential, sender_key) = self.insert_sender_key(&tx, auth.actor(), &receiver).await?;
        revoke_sender_key(&tx, &column::<String>(&row, "vault_record_ref")?).await?;
        tx.execute("UPDATE openbot_internal.automation_receivers SET current_key_revision=current_key_revision+1,vault_record_ref=$4 WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&receiver.as_str(),&credential.to_string()]).await.map_err(|_|unavailable())?;
        let id = AutomationId::try_from(column::<String>(&row, "automation_id")?)?;
        self.audit(&tx, Some(auth.actor()), &id, "automation_receiver_rotated")
            .await?;
        let receiver =
            read_receiver(&tx, &self.deployment, &self.tenant, receiver.as_str()).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AutomationReceiverSecret {
            receiver,
            sender_key,
        })
    }

    async fn revoke_receiver(
        &self,
        auth: &AuthContext,
        receiver: AutomationReceiverId,
        expected_key_revision: AutomationRevision,
    ) -> Result<AutomationReceiver, AppError> {
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        let row = self.owned_receiver(&tx, auth, &receiver).await?;
        if column::<i64>(&row, "current_key_revision")? != expected_key_revision.get() {
            return Err(AppError::AutomationKeyRevisionConflict);
        }
        // An already revoked receiver at the observed revision returns its unchanged projection.
        if column::<Option<OffsetDateTime>>(&row, "revoked_at")?.is_none() {
            tx.execute("UPDATE openbot_internal.automation_receivers SET revoked_at=statement_timestamp() WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&receiver.as_str()]).await.map_err(|_|unavailable())?;
            revoke_sender_key(&tx, &column::<String>(&row, "vault_record_ref")?).await?;
            let id = AutomationId::try_from(column::<String>(&row, "automation_id")?)?;
            self.audit(&tx, Some(auth.actor()), &id, "automation_receiver_revoked")
                .await?;
        }
        let receiver =
            read_receiver(&tx, &self.deployment, &self.tenant, receiver.as_str()).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(receiver)
    }
}

impl PostgresAutomations {
    /// Current-owner receiver row, locked; other owners and workspaces see 404.
    async fn owned_receiver(
        &self,
        tx: &Transaction<'_>,
        auth: &AuthContext,
        receiver: &AutomationReceiverId,
    ) -> Result<Row, AppError> {
        tx.query_opt("SELECT r.automation_id,r.current_key_revision,r.revoked_at,r.vault_record_ref
            FROM openbot_internal.automation_receivers r JOIN openbot_internal.automation_definitions d
              ON (d.deployment_id,d.tenant_id,d.automation_id)=(r.deployment_id,r.tenant_id,r.automation_id)
            WHERE r.deployment_id=$1 AND r.tenant_id=$2 AND r.receiver_id=$3 AND d.owner_id=$4 FOR UPDATE OF r",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&receiver.as_str(),&auth.actor().as_str()])
            .await.map_err(|_|unavailable())?.ok_or(AppError::NotVisible)
    }

    /// Mint a 256-bit key and seal it into one new `public.credentials` row of this transaction.
    async fn insert_sender_key(
        &self,
        tx: &Transaction<'_>,
        owner: &ActorId,
        receiver: &AutomationReceiverId,
    ) -> Result<(Uuid, AutomationSenderKey), AppError> {
        use std::fmt::Write as _;
        let mut random = zeroize::Zeroizing::new([0_u8; 32]);
        getrandom::fill(random.as_mut()).map_err(|_| unavailable())?;
        let mut hex = zeroize::Zeroizing::new(String::with_capacity(64));
        for byte in random.iter() {
            write!(hex, "{byte:02x}").map_err(|_| unavailable())?;
        }
        let sender_key =
            AutomationSenderKey::new(std::mem::take(&mut *hex)).map_err(|_| unavailable())?;
        let credential = Uuid::now_v7();
        let sealed = self
            .vault
            .seal(
                &credential,
                SecretKind::Agent,
                SecretPrincipal::Actor(owner.clone()),
                SecretPrincipal::Service(ServiceId::new(format!(
                    "automation_receiver:{}",
                    receiver.as_str()
                ))),
                &SecretBytes::new(sender_key.expose().as_bytes().to_vec()),
            )
            .map_err(|_| unavailable())?;
        tx.execute("INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata,revoked_at,created_at,updated_at)
            VALUES($1,'agent','automation_receiver',$2,$3,'{}'::jsonb,NULL,clock_timestamp(),clock_timestamp())",
            &[&credential,&sealed,&receiver.as_str()]).await.map_err(|_|unavailable())?;
        Ok((credential, sender_key))
    }
}

async fn revoke_sender_key(tx: &Transaction<'_>, credential: &str) -> Result<(), AppError> {
    tx.execute("UPDATE public.credentials SET revoked_at=coalesce(revoked_at,clock_timestamp()),updated_at=clock_timestamp()
        WHERE id=$1::text::uuid AND kind='agent' AND provider='automation_receiver'",
        &[&credential]).await.map_err(|_|unavailable())?;
    Ok(())
}

/// Secret-free receiver projection with its content-free refusal intervals.
pub(crate) async fn read_receiver(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    receiver: &str,
) -> Result<AutomationReceiver, AppError> {
    let row = tx.query_one("SELECT r.*,(SELECT COALESCE(jsonb_agg(jsonb_build_object('reason',f.reason_code,'count',f.count,'firstAt',f.first_at,'lastAt',f.last_at) ORDER BY f.reason_code),'[]')
          FROM openbot_internal.automation_receiver_refusals f WHERE (f.deployment_id,f.tenant_id,f.receiver_id)=(r.deployment_id,r.tenant_id,r.receiver_id)) AS refusals
        FROM openbot_internal.automation_receivers r WHERE r.deployment_id=$1 AND r.tenant_id=$2 AND r.receiver_id=$3",
        &[&deployment.as_str(),&tenant.as_str(),&receiver]).await.map_err(|_|unavailable())?;
    Ok(AutomationReceiver {
        id: column::<String>(&row, "receiver_id")?.try_into()?,
        automation_id: column::<String>(&row, "automation_id")?.try_into()?,
        adapter: string_value(column(&row, "adapter")?)?,
        source_principal: stored(column(&row, "source_principal")?)?,
        event_filter: stored(column(&row, "event_filter")?)?,
        key_revision: column::<i64>(&row, "current_key_revision")?.try_into()?,
        revoked_at: column(&row, "revoked_at")?,
        refusals: stored(column(&row, "refusals")?)?,
    })
}

impl PostgresAutomations {
    async fn mutate(
        &self,
        auth: &AuthContext,
        id: AutomationId,
        input: AutomationUpdate,
        tombstone: bool,
    ) -> Result<AutomationDefinition, AppError> {
        if let AutomationUpdate::Replace { config, .. } = &input {
            super::time::validate_draft(config)?;
        }
        let expected = match &input {
            AutomationUpdate::Replace {
                expected_revision, ..
            }
            | AutomationUpdate::Enable {
                expected_revision, ..
            }
            | AutomationUpdate::Pause { expected_revision }
            | AutomationUpdate::Revoke { expected_revision } => expected_revision.get(),
        };
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        self.prepare(&tx, auth).await?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let row = self.definition_row(&tx, auth, &id, true).await?;
        if column::<i64>(&row, "current_revision")? != expected {
            return Err(AppError::AutomationRevisionConflict);
        }
        if column::<String>(&row, "state")? == "tombstoned" {
            return Err(AppError::AutomationNotAccepting);
        }
        let revision = expected
            .checked_add(1)
            .ok_or(AppError::AutomationRevisionConflict)?;
        let mut config: AutomationConfigV1 = stored(column(&row, "config_snapshot")?)?;
        let mut delegation_revision: Option<i64> = column(&row, "delegation_revision")?;
        let old_enabled = column::<String>(&row, "state")? == "enabled";
        let (state, revoke, terminate, action) = match input {
            AutomationUpdate::Replace {
                config: replacement,
                ..
            } => {
                if replacement.wire().bot_id != config.bot_id {
                    return Err(AppError::MalformedPayload { field: "bot_id" });
                }
                let next = &replacement.wire().permission_ceiling;
                let revoke = if old_enabled {
                    true
                } else if &config.permission_ceiling != next
                    && let Some(grant_revision) = delegation_revision
                    && let Some(grant) = tx
                        .query_opt(
                            "SELECT grant_snapshot FROM openbot_internal.automation_delegations
                             WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3
                               AND delegation_revision=$4 AND revoked_at IS NULL",
                            &[
                                &self.deployment.as_str(),
                                &self.tenant.as_str(),
                                &id.as_str(),
                                &grant_revision,
                            ],
                        )
                        .await
                        .map_err(|_| unavailable())?
                {
                    // A paused draft can only reduce permissions in the frozen grant.
                    let grant: AutomationDelegationV1 = stored(column(&grant, "grant_snapshot")?)?;
                    grant.tool_ids.iter().any(|id| !next.tool_ids.contains(id))
                        || grant
                            .data_scopes
                            .iter()
                            .any(|id| !next.data_scopes.contains(id))
                } else {
                    false
                };
                config = replacement.wire().clone();
                (
                    "paused",
                    revoke,
                    Some(("superseded", "automation_revision_superseded")),
                    "automation_replaced",
                )
            }
            AutomationUpdate::Enable { grant_consent, .. } => {
                if matches!(config.trigger, AutomationTrigger::Cron { .. }) {
                    return Err(AppError::AutomationTriggerUnavailable);
                }
                let facts = crate::delegation::owner_snapshot(
                    &tx,
                    &self.deployment,
                    &self.tenant,
                    auth.actor(),
                    &config.bot_id,
                )
                .await?;
                if facts.revoked
                    || !facts.bot_visible
                    || facts.auth_generation != auth.auth_generation()
                {
                    return Err(AppError::AutomationDelegationInvalid);
                }
                verify_thread(&tx, &self.deployment, &self.tenant, &row).await?;
                crate::automation_budget::ensure_configured(
                    &tx,
                    &self.deployment,
                    &self.tenant,
                    auth.actor().as_str(),
                    id.as_str(),
                    &config.budget,
                )
                .await?;
                let requested_expiry = match grant_consent.validity {
                    AutomationGrantValidity::UntilRevoked {} => None,
                    AutomationGrantValidity::Expires { expires_at } => Some(expires_at),
                };
                let times = tx
                    .query_one(
                        "SELECT statement_timestamp(), $1::timestamptz",
                        &[&requested_expiry],
                    )
                    .await
                    .map_err(|_| unavailable())?;
                let now: OffsetDateTime = times.get(0);
                let expires: Option<OffsetDateTime> = times.get(1);
                let (validity, snapshot_validity) = match expires {
                    None => ("until_revoked", AutomationGrantValidity::UntilRevoked {}),
                    Some(expires_at) if expires_at > now => {
                        ("expires", AutomationGrantValidity::Expires { expires_at })
                    }
                    Some(_) => {
                        return Err(AppError::MalformedPayload {
                            field: "expires_at",
                        });
                    }
                };
                // Re-authorization only appends. Every un-revoked grant is already within this
                // ceiling (a narrower paused edit revokes them), so an active Run keeps its grant.
                let generation =
                    i64::try_from(auth.auth_generation().get()).map_err(|_| unavailable())?;
                let thread = ThreadId::new(column::<String>(&row, "thread_id")?);
                let snapshot = AutomationDelegationV1 {
                    schema_version: AutomationSchemaVersion,
                    owner_id: auth.actor().clone(),
                    deployment_id: self.deployment.clone(),
                    tenant_id: self.tenant.clone(),
                    bot_id: config.bot_id.clone(),
                    thread_id: thread.clone(),
                    definition_revision: revision.try_into()?,
                    tool_ids: config.permission_ceiling.tool_ids.clone(),
                    data_scopes: config.permission_ceiling.data_scopes.clone(),
                    budget_policy_revision: revision.try_into()?,
                    auth_generation: generation,
                    validity: snapshot_validity,
                    template: config.prompt_template.clone(),
                    run_deadline_seconds: u16::try_from(config.run_deadline_seconds)
                        .map_err(|_| unavailable())?,
                };
                tx.execute("INSERT INTO openbot_internal.automation_delegations(deployment_id,tenant_id,automation_id,delegation_revision,owner_id,bot_id,thread_id,granted_auth_generation,grant_snapshot,validity,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&revision,&auth.actor().as_str(),&config.bot_id.as_str(),&thread.as_str(),&generation,&serde_json::to_value(snapshot).map_err(|_|unavailable())?,&validity,&expires]).await.map_err(|_|unavailable())?;
                delegation_revision = Some(revision);
                (
                    "enabled",
                    false,
                    old_enabled.then_some(("superseded", "automation_revision_superseded")),
                    "automation_enabled",
                )
            }
            AutomationUpdate::Pause { .. } => (
                "paused",
                false,
                Some(("terminated_by_pause", "automation_paused")),
                "automation_paused",
            ),
            AutomationUpdate::Revoke { .. } if tombstone => (
                "tombstoned",
                true,
                Some(("terminated_by_pause", "automation_tombstoned")),
                "automation_tombstoned",
            ),
            AutomationUpdate::Revoke { .. } => (
                "paused",
                true,
                Some(("terminated_by_pause", "automation_paused")),
                "automation_revoked",
            ),
        };
        if revoke {
            tx.execute("UPDATE openbot_internal.automation_delegations SET revoked_at=statement_timestamp() WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND revoked_at IS NULL",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?;
            if let Some(active)=tx.query_opt("SELECT o.run_id FROM openbot_internal.automation_occurrences o JOIN public.runs r ON r.run_id=o.run_id WHERE o.deployment_id=$1 AND o.tenant_id=$2 AND o.automation_id=$3 AND r.status='running' ORDER BY o.accepted_at LIMIT 1",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str()]).await.map_err(|_|unavailable())?{
                crate::thread_directory::cancel_automation_run(&tx,&self.deployment,&self.tenant,&row,
                    &RunId::new(column::<String>(&active,"run_id")?)).await.map_err(|e| e.into_app_error())?;
            }
        }
        if let Some((terminal, reason)) = terminate {
            let changed=tx.execute("UPDATE openbot_internal.automation_occurrences SET state=$4,reason_code=$5,terminal_at=statement_timestamp() WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 AND state IN ('pending','blocked_budget','blocked_model')",
                &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&terminal,&reason]).await.map_err(|_|unavailable())?;
            adjust_pending(
                &tx,
                &self.deployment,
                &self.tenant,
                &id,
                -i64::try_from(changed).map_err(|_| unavailable())?,
            )
            .await?;
        }
        let snapshot = serde_json::to_value(&config).map_err(|_| unavailable())?;
        tx.execute("INSERT INTO openbot_internal.automation_definition_revisions(deployment_id,tenant_id,automation_id,revision,config_snapshot,delegation_revision) VALUES($1,$2,$3,$4,$5,$6)",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&revision,&snapshot,&delegation_revision]).await.map_err(|_|unavailable())?;
        tx.execute("UPDATE openbot_internal.automation_definitions SET current_revision=$4,state=$5,updated_at=statement_timestamp(),tombstoned_at=CASE WHEN $5='tombstoned' THEN statement_timestamp() ELSE NULL END WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&id.as_str(),&revision,&state]).await.map_err(|_|unavailable())?;
        crate::automation_budget::replace_automation_policy(
            &tx,
            &self.deployment,
            &self.tenant,
            &id,
            revision,
            &config.budget,
        )
        .await?;
        self.audit(&tx, Some(auth.actor()), &id, action).await?;
        let current = self.definition_row(&tx, auth, &id, false).await?;
        let projection = self.projection(&tx, &current).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(projection)
    }
}

pub(crate) async fn lock_workspace(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
) -> Result<(), AppError> {
    tx.execute("INSERT INTO openbot_internal.automation_workspace_capacity(deployment_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&deployment.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?;
    tx.query_one("SELECT pending_count,active_count FROM openbot_internal.automation_workspace_capacity WHERE deployment_id=$1 AND tenant_id=$2 FOR UPDATE",&[&deployment.as_str(),&tenant.as_str()]).await.map_err(|_|unavailable())?;
    Ok(())
}
pub(crate) async fn adjust_pending(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    id: &AutomationId,
    delta: i64,
) -> Result<(), AppError> {
    tx.execute("UPDATE openbot_internal.automation_workspace_capacity SET pending_count=pending_count+$3 WHERE deployment_id=$1 AND tenant_id=$2",&[&deployment.as_str(),&tenant.as_str(),&delta]).await.map_err(|_|unavailable())?;
    tx.execute("UPDATE openbot_internal.automation_definitions SET pending_count=pending_count+$4 WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3",&[&deployment.as_str(),&tenant.as_str(),&id.as_str(),&delta]).await.map_err(|_|unavailable())?;
    Ok(())
}

/// Core scalar FKs do not imply these scope, owner, Bot or exclusive-Thread facts.
pub(crate) async fn verify_thread(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    definition: &Row,
) -> Result<(), AppError> {
    let valid:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM public.threads t
        WHERE t.thread_id=$1 AND t.deployment_id=$2 AND t.tenant_id=$3 AND t.created_by=$4
          AND t.anchor_kind='direct_bot' AND t.anchor_id=$5 AND t.status='active' AND t.deleted_at IS NULL
          AND (SELECT count(*) FROM public.thread_memberships m WHERE m.thread_id=t.thread_id)=1
          AND EXISTS(SELECT 1 FROM public.thread_memberships m WHERE m.thread_id=t.thread_id AND m.user_id=$4))",
        &[&column::<String>(definition,"thread_id")?,&deployment.as_str(),&tenant.as_str(),&column::<String>(definition,"owner_id")?,&column::<String>(definition,"bot_id")?]).await.map_err(|_|unavailable())?.get(0);
    if !valid {
        return Err(AppError::AutomationDelegationInvalid);
    }
    Ok(())
}

pub(crate) async fn valid_grant(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    definition: &Row,
) -> Result<AutomationDelegationV1, AppError> {
    verify_thread(tx, deployment, tenant, definition).await?;
    let id: String = column(definition, "automation_id")?;
    let revision: Option<i64> = column(definition, "delegation_revision")?;
    let Some(revision) = revision else {
        return Err(AppError::AutomationDelegationInvalid);
    };
    let grant=tx.query_opt("SELECT g.grant_snapshot FROM openbot_internal.automation_delegations g JOIN public.users u ON u.id=g.owner_id
        WHERE g.deployment_id=$1 AND g.tenant_id=$2 AND g.automation_id=$3 AND g.delegation_revision=$4
          AND g.owner_id=$5 AND g.bot_id=$6 AND g.thread_id=$7 AND g.revoked_at IS NULL
          AND (g.expires_at IS NULL OR g.expires_at>statement_timestamp())
          AND g.granted_auth_generation=COALESCE(u.auth_generation,0)
          AND NOT EXISTS(SELECT 1 FROM public.revoked_access a WHERE a.email=lower(u.email))
          AND EXISTS(SELECT 1 FROM public.agents a JOIN public.agent_profiles p ON p.agent_id=a.id
              LEFT JOIN public.deployment_packages dp ON dp.id=a.package_id WHERE a.id=g.bot_id AND p.deleted_at IS NULL
              AND (a.package_id IS NULL OR dp.tenant_id=g.tenant_id)
              AND (p.visibility='public' OR p.owner_user_id=g.owner_id OR EXISTS(SELECT 1 FROM public.user_roles r WHERE r.user_id=g.owner_id AND r.role='admin')))
        FOR SHARE OF g,u",
        &[&deployment.as_str(),&tenant.as_str(),&id,&revision,&column::<String>(definition,"owner_id")?,&column::<String>(definition,"bot_id")?,&column::<String>(definition,"thread_id")?]).await.map_err(|_|unavailable())?.ok_or(AppError::AutomationDelegationInvalid)?;
    stored(column(&grant, "grant_snapshot")?)
}

pub(crate) fn column<T: for<'a> FromSql<'a>>(row: &Row, name: &str) -> Result<T, AppError> {
    row.try_get(name).map_err(|_| unavailable())
}
pub(crate) fn stored<T: DeserializeOwned>(value: Value) -> Result<T, AppError> {
    serde_json::from_value(value).map_err(|_| unavailable())
}
fn string_value<T: DeserializeOwned>(value: String) -> Result<T, AppError> {
    stored(Value::String(value))
}
pub(crate) fn unavailable() -> AppError {
    AppError::DependencyUnavailable {
        dependency: "automation_store",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    binding: String,
    nanos: String,
    id: String,
}
fn binding(auth: &AuthContext, namespace: &str) -> Result<String, AppError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&(auth.deployment(), auth.tenant(), auth.actor(), namespace))
        .map_err(|_| unavailable())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn decode_cursor(
    raw: Option<&str>,
    auth: &AuthContext,
    namespace: &str,
) -> Result<Option<(OffsetDateTime, String)>, AppError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let malformed = || AppError::MalformedPayload { field: "cursor" };
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| malformed())?;
    let cursor: Cursor = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
    if cursor.binding != binding(auth, namespace)? {
        return Err(malformed());
    }
    let at =
        OffsetDateTime::from_unix_timestamp_nanos(cursor.nanos.parse().map_err(|_| malformed())?)
            .map_err(|_| malformed())?;
    Ok(Some((at, cursor.id)))
}
fn next_cursor(
    rows: &[Row],
    limit: u32,
    auth: &AuthContext,
    namespace: &str,
    time_column: &str,
    id_column: &str,
) -> Result<Option<String>, AppError> {
    if rows.len() <= limit as usize {
        return Ok(None);
    }
    let row = &rows[limit as usize - 1];
    let cursor = Cursor {
        binding: binding(auth, namespace)?,
        nanos: column::<OffsetDateTime>(row, time_column)?
            .unix_timestamp_nanos()
            .to_string(),
        id: column(row, id_column)?,
    };
    Ok(Some(URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&cursor).map_err(|_| unavailable())?,
    )))
}

async fn read_receipt(
    tx: &Transaction<'_>,
    deployment: &DeploymentId,
    tenant: &TenantId,
    owner: &str,
    id: &str,
) -> Result<AutomationReceipt, AppError> {
    let delivery = if id.starts_with("adel:") {
        tx.query_opt("SELECT v.* FROM openbot_internal.automation_deliveries v JOIN openbot_internal.automation_definitions d ON (d.deployment_id,d.tenant_id,d.automation_id)=(v.deployment_id,v.tenant_id,v.automation_id) WHERE v.receipt_id=$1 AND d.deployment_id=$2 AND d.tenant_id=$3 AND d.owner_id=$4",&[&id,&deployment.as_str(),&tenant.as_str(),&owner]).await.map_err(|_|unavailable())?
    } else {
        None
    };
    if id.starts_with("adel:") && delivery.is_none() {
        return Err(AppError::NotVisible);
    }
    let alias = delivery
        .as_ref()
        .map(|r| column::<Option<String>>(r, "alias_of"))
        .transpose()?
        .flatten();
    let occurrence = if alias.is_none() {
        tx.query_opt("SELECT o.*,d.thread_id,r.status AS run_status,
            (SELECT m.message_id FROM public.messages m JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=r.terminal_event_seq AND e.terminal
              WHERE m.run_id=r.run_id AND m.thread_id=d.thread_id AND m.message_id=r.run_id||':assistant' AND m.role='assistant') AS result_ref,
            v.receiver_id,v.source_event_key,v.data_cleared_at
            FROM openbot_internal.automation_occurrences o
            JOIN openbot_internal.automation_definitions d ON (d.deployment_id,d.tenant_id,d.automation_id)=(o.deployment_id,o.tenant_id,o.automation_id)
            LEFT JOIN public.runs r ON r.run_id=o.run_id AND r.thread_id=d.thread_id
            LEFT JOIN openbot_internal.automation_deliveries v ON v.receipt_id=o.delivery_receipt_id AND v.deployment_id=o.deployment_id AND v.tenant_id=o.tenant_id
            WHERE (o.occurrence_id=$1 OR o.delivery_receipt_id=$1) AND d.deployment_id=$2 AND d.tenant_id=$3 AND d.owner_id=$4",
            &[&id,&deployment.as_str(),&tenant.as_str(),&owner]).await.map_err(|_|unavailable())?
    } else {
        None
    };
    if let Some(row) = occurrence {
        let source = match column::<String>(&row, "trigger_kind")?.as_str() {
            "manual" => AutomationReceiptSource::Manual {
                operation_id: column::<String>(&row, "manual_operation_id")?.try_into()?,
            },
            "cron" => AutomationReceiptSource::Cron {
                planned_at: column(&row, "planned_at")?,
            },
            "event" => AutomationReceiptSource::Event {
                receiver_id: column::<String>(&row, "receiver_id")?.try_into()?,
                event_id: column::<String>(&row, "source_event_key")?.try_into()?,
            },
            _ => return Err(unavailable()),
        };
        let projection = AutomationOccurrence {
            id: column::<String>(&row, "occurrence_id")?.try_into()?,
            state: string_value(column(&row, "state")?)?,
            reason_code: column::<Option<String>>(&row, "reason_code")?
                .map(string_value)
                .transpose()?,
            expires_at: column(&row, "expires_at")?,
            thread_id: ThreadId::new(column::<String>(&row, "thread_id")?),
            run_id: column::<Option<String>>(&row, "run_id")?.map(RunId::new),
            run_status: column::<Option<String>>(&row, "run_status")?
                .map(string_value)
                .transpose()?,
            result_ref: column(&row, "result_ref")?,
        };
        return Ok(AutomationReceipt {
            receipt_id: id.to_owned().try_into()?,
            automation_id: column::<String>(&row, "automation_id")?.try_into()?,
            definition_revision: column::<i64>(&row, "definition_revision")?.try_into()?,
            source,
            status: AutomationDeliveryStatus::Accepted,
            received_at: column(&row, "accepted_at")?,
            occurrence: Some(projection),
            alias_of: None,
            data_cleared: column::<Option<OffsetDateTime>>(&row, "data_cleared_at")?.is_some(),
        });
    }
    let row = delivery.ok_or(AppError::NotVisible)?;
    Ok(AutomationReceipt {
        receipt_id: id.to_owned().try_into()?,
        automation_id: column::<String>(&row, "automation_id")?.try_into()?,
        definition_revision: column::<i64>(&row, "definition_revision")?.try_into()?,
        source: AutomationReceiptSource::Event {
            receiver_id: column::<String>(&row, "receiver_id")?.try_into()?,
            event_id: column::<String>(&row, "source_event_key")?.try_into()?,
        },
        status: string_value(column(&row, "status")?)?,
        received_at: column(&row, "received_at")?,
        occurrence: None,
        alias_of: alias.map(AutomationReceiptId::try_from).transpose()?,
        data_cleared: column::<Option<OffsetDateTime>>(&row, "data_cleared_at")?.is_some(),
    })
}
