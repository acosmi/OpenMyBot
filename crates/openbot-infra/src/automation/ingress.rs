//! Sender-key authentication and the same-PG event acceptance transaction.

use super::{
    PostgresAutomations,
    store::{adjust_pending, column, lock_workspace, stored, unavailable},
};
use async_trait::async_trait;
use openbot_application::automation::AutomationDeliveries;
use openbot_contracts::{automation::*, error::AppError, ids::ActorId};
use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
use serde_json::json;
use uuid::Uuid;

#[async_trait]
impl AutomationDeliveries for PostgresAutomations {
    async fn authenticate(
        &self,
        receiver: &AutomationReceiverId,
        presented: &SecretBytes,
    ) -> Result<AutomationRevision, AppError> {
        // The 5 s SQL precedent of the other standalone credential resolutions.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let admission = self
            .recovery_gate
            .borrow_worker_before(deadline)
            .await
            .map_err(|_| unavailable())?;
        let client = self.pool.get().await.map_err(|_| unavailable())?;
        // Revoked receivers, revoked key rows (including an administrator revocation) and
        // unknown receivers are indistinguishable to the sender.
        let row = client.query_opt("SELECT r.current_key_revision,d.owner_id,c.id AS credential,c.encrypted_value
            FROM openbot_internal.automation_receivers r
            JOIN openbot_internal.automation_definitions d ON (d.deployment_id,d.tenant_id,d.automation_id)=(r.deployment_id,r.tenant_id,r.automation_id)
            JOIN public.credentials c ON c.id=r.vault_record_ref::uuid AND c.kind='agent' AND c.provider='automation_receiver'
              AND c.key_id=r.receiver_id AND c.revoked_at IS NULL
            WHERE r.deployment_id=$1 AND r.tenant_id=$2 AND r.receiver_id=$3 AND r.revoked_at IS NULL",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&receiver.as_str()]).await.map_err(|_|unavailable())?
            .ok_or(AppError::AutomationSourceUnauthorized)?;
        let credential = column::<Uuid>(&row, "credential")?;
        // A restored key stays closed until its credential requirement has a receipt
        // (spec revision R485 ¶1467): the sender sees the same refusal as a revoked key.
        crate::restore_reconfirmation::require_confirmed_before(
            &**client,
            crate::restore_reconfirmation::RequirementSource {
                cohort: admission.restore_cohort(),
                kind: crate::restore_reconfirmation::RequirementKind::Credential,
                source_ref: &credential.to_string(),
            },
            deadline,
        )
        .await
        .map_err(|error| match error {
            crate::restore_reconfirmation::RestoreReconfirmationError::NotConfirmed => {
                AppError::AutomationSourceUnauthorized
            }
            _ => unavailable(),
        })?;
        drop(client);
        admission
            .verify_current_before(deadline)
            .map_err(|_| unavailable())?;
        let stored_key = self
            .vault
            .open(
                &credential,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new(column::<String>(&row, "owner_id")?)),
                SecretPrincipal::Service(ServiceId::new(format!(
                    "automation_receiver:{}",
                    receiver.as_str()
                ))),
                &column::<String>(&row, "encrypted_value")?,
            )
            // An unavailable KEK or rejected ciphertext is a host fault, not a sender fault.
            .map_err(|_| AppError::DependencyUnavailable {
                dependency: "credential_vault",
            })?
            .into_secret();
        if !stored_key.ct_eq(presented) {
            return Err(AppError::AutomationSourceUnauthorized);
        }
        Ok(column::<i64>(&row, "current_key_revision")?.try_into()?)
    }

    async fn admit(
        &self,
        delivery: VerifiedAutomationDelivery,
    ) -> Result<AutomationIngressOutcome, AppError> {
        let scope = [self.deployment.as_str(), self.tenant.as_str()];
        let receiver = delivery.receiver_id().as_str();
        let mut client = self.pool.get().await.map_err(|_| unavailable())?;
        let tx = client.transaction().await.map_err(|_| unavailable())?;
        tx.batch_execute("SET LOCAL lock_timeout='4s'; SET LOCAL statement_timeout='4s'")
            .await
            .map_err(|_| unavailable())?;
        crate::thread_history_writer::CurrentWriterSchema::observe(&tx)
            .await
            .map_err(|_| unavailable())?;
        lock_workspace(&tx, &self.deployment, &self.tenant).await?;
        let automation: String = tx
            .query_opt(
                "SELECT automation_id FROM openbot_internal.automation_receivers
                 WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3",
                &[&scope[0], &scope[1], &receiver],
            )
            .await
            .map_err(|_| unavailable())?
            .ok_or(AppError::AutomationSourceUnauthorized)?
            .get(0);
        let id = AutomationId::try_from(automation)?;
        let definition = tx.query_one("SELECT state,current_revision,pending_count FROM openbot_internal.automation_definitions
            WHERE deployment_id=$1 AND tenant_id=$2 AND automation_id=$3 FOR UPDATE",
            &[&scope[0],&scope[1],&id.as_str()]).await.map_err(|_|unavailable())?;
        // Rotation and revocation lock only this receiver row; taking it FOR UPDATE and comparing
        // the key revision below is what makes a change committed after authentication refuse here.
        let current = tx.query_one("SELECT r.current_key_revision,r.revoked_at IS NULL AS active,r.adapter,r.source_principal,r.event_filter,r.dedup_count,
                EXISTS(SELECT 1 FROM public.credentials c WHERE c.id=r.vault_record_ref::uuid AND c.revoked_at IS NULL) AS key_active
            FROM openbot_internal.automation_receivers r WHERE r.deployment_id=$1 AND r.tenant_id=$2 AND r.receiver_id=$3 FOR UPDATE",
            &[&scope[0],&scope[1],&receiver]).await.map_err(|_|unavailable())?;
        let principal: serde_json::Value = column(&current, "source_principal")?;
        if !column::<bool>(&current, "active")?
            || !column::<bool>(&current, "key_active")?
            || column::<i64>(&current, "current_key_revision")? != delivery.key_revision().get()
            || column::<String>(&current, "adapter")? != delivery.adapter().as_str()
            || stored::<AutomationSourcePrincipal>(principal)? != *delivery.source_principal()
        {
            return Err(AppError::AutomationSourceUnauthorized);
        }
        if let Some(previous) = tx
            .query_opt(
                "SELECT receipt_id,fingerprint,status FROM openbot_internal.automation_deliveries
            WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3 AND source_event_key=$4",
                &[
                    &scope[0],
                    &scope[1],
                    &receiver,
                    &delivery.source_event_key().as_str(),
                ],
            )
            .await
            .map_err(|_| unavailable())?
        {
            if column::<Vec<u8>>(&previous, "fingerprint")? != delivery.fingerprint() {
                return Err(AppError::AutomationEventConflict);
            }
            let replay = AutomationIngressReceipt {
                receipt_id: column::<String>(&previous, "receipt_id")?.try_into()?,
                status: stored(serde_json::Value::String(column(&previous, "status")?))?,
            };
            tx.rollback().await.map_err(|_| unavailable())?;
            return Ok(AutomationIngressOutcome::Replayed(replay));
        }
        if column::<String>(&definition, "state")? != "enabled" {
            return Err(AppError::AutomationNotAccepting);
        }
        let filter: AutomationEventFilter = stored(column(&current, "event_filter")?)?;
        if !filter.accepts(delivery.event_type(), &delivery.normalized_data()["data"]) {
            return Err(AppError::EventNotAccepted);
        }
        if let Some(occurred_at) = delivery.occurred_at() {
            let outside: bool = tx
                .query_one(
                    "SELECT $1::timestamptz<statement_timestamp()-interval '24 hours'
                        OR $1::timestamptz>statement_timestamp()+interval '5 minutes'",
                    &[&occurred_at],
                )
                .await
                .map_err(|_| unavailable())?
                .get(0);
            if outside {
                return Err(AppError::EventOutsideWindow);
            }
        }
        let admitted = take_token(
            &mut *self.rate.lock().map_err(|_| unavailable())?,
            receiver,
            std::time::Instant::now(),
        );
        if !admitted {
            return Err(AppError::AutomationRateLimited);
        }
        if column::<i64>(&current, "dedup_count")? >= 1_000_000 {
            return Err(AppError::AutomationReceiverFull);
        }
        let workspace: i64 = tx.query_one("SELECT pending_count FROM openbot_internal.automation_workspace_capacity WHERE deployment_id=$1 AND tenant_id=$2",
            &[&scope[0],&scope[1]]).await.map_err(|_|unavailable())?.get(0);
        if column::<i64>(&definition, "pending_count")? >= 100 || workspace >= 1000 {
            return Err(AppError::AutomationCapacityExceeded);
        }
        let revision: i64 = column(&definition, "current_revision")?;
        let receipt = format!("adel:{}", Uuid::now_v7());
        let occurrence = format!("aocc:{}", Uuid::now_v7());
        tx.execute("INSERT INTO openbot_internal.automation_deliveries(receipt_id,deployment_id,tenant_id,automation_id,receiver_id,source_event_key,key_revision,definition_revision,fingerprint,verified_body_digest,status,normalized_data,terminal_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'accepted',$11,statement_timestamp())",
            &[&receipt,&scope[0],&scope[1],&id.as_str(),&receiver,&delivery.source_event_key().as_str(),&delivery.key_revision().get(),&revision,
              &delivery.fingerprint().as_slice(),&delivery.verified_body_digest().map(<[u8;32]>::as_slice),delivery.normalized_data()]).await.map_err(|_|unavailable())?;
        let intent = json!({"schemaVersion":1,"kind":"event","receiptId":receipt,"definitionRevision":revision});
        tx.execute("INSERT INTO openbot_internal.automation_occurrences(occurrence_id,deployment_id,tenant_id,automation_id,definition_revision,trigger_kind,delivery_receipt_id,intent_snapshot,state)
            VALUES($1,$2,$3,$4,$5,'event',$6,$7,'pending')",
            &[&occurrence,&scope[0],&scope[1],&id.as_str(),&revision,&receipt,&intent]).await.map_err(|_|unavailable())?;
        tx.execute("UPDATE openbot_internal.automation_receivers SET dedup_count=dedup_count+1 WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3",
            &[&scope[0],&scope[1],&receiver]).await.map_err(|_|unavailable())?;
        adjust_pending(&tx, &self.deployment, &self.tenant, &id, 1).await?;
        tx.execute("INSERT INTO public.outbox(outbox_id,aggregate_kind,aggregate_id,seq,destination,delivery_class,payload) VALUES($1,'automation',$2,0,'automation.dispatch','internal',$3)",
            &[&format!("{occurrence}:automation_dispatch"),&occurrence,&json!({"automationId":id,"occurrenceId":occurrence})]).await.map_err(|_|unavailable())?;
        tx.query_one("SELECT pg_notify('openbot_automation',$1)", &[&id.as_str()])
            .await
            .map_err(|_| unavailable())?;
        self.audit(&tx, None, &id, "automation_event_accepted")
            .await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(AutomationIngressOutcome::Accepted(
            AutomationIngressReceipt {
                receipt_id: receipt.try_into()?,
                status: AutomationDeliveryStatus::Accepted,
            },
        ))
    }

    async fn record_refusal(
        &self,
        receiver: &AutomationReceiverId,
        reason: AutomationRefusalReason,
    ) -> Result<(), AppError> {
        let client = self.pool.get().await.map_err(|_| unavailable())?;
        client.execute("INSERT INTO openbot_internal.automation_receiver_refusals AS f(deployment_id,tenant_id,receiver_id,reason_code,count)
            SELECT $1,$2,$3,$4,1 WHERE EXISTS(SELECT 1 FROM openbot_internal.automation_receivers WHERE deployment_id=$1 AND tenant_id=$2 AND receiver_id=$3)
            ON CONFLICT (deployment_id,tenant_id,receiver_id,reason_code) DO UPDATE SET count=f.count+1,last_at=statement_timestamp()",
            &[&self.deployment.as_str(),&self.tenant.as_str(),&receiver.as_str(),&reason.as_str()]).await.map_err(|_|unavailable())?;
        Ok(())
    }
}

// Per-receiver process token bucket: burst 20, refilled at 10 per second.
fn take_token(
    buckets: &mut std::collections::HashMap<String, (std::time::Instant, f64)>,
    receiver: &str,
    now: std::time::Instant,
) -> bool {
    let (last, tokens) = buckets.entry(receiver.to_owned()).or_insert((now, 20.0));
    let available = (*tokens + now.duration_since(*last).as_secs_f64() * 10.0).min(20.0);
    *last = now;
    *tokens = if available < 1.0 {
        available
    } else {
        available - 1.0
    };
    available >= 1.0
}

#[cfg(test)]
mod tests {
    use super::take_token;
    use std::time::{Duration, Instant};

    #[test]
    fn sender_rate_is_burst_twenty_and_ten_per_second_per_receiver() {
        let mut buckets = std::collections::HashMap::new();
        let start = Instant::now();
        assert!((0..20).all(|_| take_token(&mut buckets, "a", start)));
        assert!(!take_token(&mut buckets, "a", start));
        assert!(
            take_token(&mut buckets, "b", start),
            "receivers are independent"
        );
        let later = start + Duration::from_millis(100);
        assert!(take_token(&mut buckets, "a", later));
        assert!(!take_token(&mut buckets, "a", later));
        let refilled = later + Duration::from_secs(10);
        assert_eq!(
            (0..25)
                .filter(|_| take_token(&mut buckets, "a", refilled))
                .count(),
            20
        );
    }
}

/// A restored receiver key is a `credential` requirement of the cohort: before
/// its receipt the sender is refused as unauthorized without a Vault-open;
/// after one receipt the same key opens once and authenticates.
#[cfg(all(test, feature = "desktop-local", target_os = "macos"))]
mod restore_gate {
    use crate::recovery_control::tests::restore_current::RestoreCurrentFixture;
    use openbot_application::automation::AutomationDeliveries as _;
    use openbot_contracts::{
        automation::AutomationReceiverId,
        error::AppError,
        ids::{ActorId, DeploymentId, TenantId},
    };
    use openbot_domain::vault::{
        KeyVersion, SecretBytes, SecretKind, SecretPrincipal, ServiceId, WrappingKey,
    };

    #[tokio::test]
    #[ignore = "requires OPENBOT_TEST_PG_BIN PostgreSQL 17.11 for an owned candidate"]
    async fn t046_32_unconfirmed_receiver_key_opens_no_vault() {
        let vault = crate::vault::CredentialRecordVault::single_key(
            TenantId::new("ten"),
            KeyVersion::new(1),
            WrappingKey::from_bytes(vec![0x56; 32]).unwrap(),
        );
        let credential = uuid::Uuid::now_v7();
        let sealed = vault
            .seal(
                &credential,
                SecretKind::Agent,
                SecretPrincipal::Actor(ActorId::new("owner")),
                SecretPrincipal::Service(ServiceId::new("automation_receiver:receiver-r")),
                &SecretBytes::new(b"restored-sender-key".to_vec()),
            )
            .unwrap();
        let seed = format!(
            "INSERT INTO public.users(id,email,auth_generation) VALUES('owner','owner@restored.example.test',0);
             INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status) VALUES('automation-thread','ten','dep','owner','direct_bot','bot-1','active');
             INSERT INTO openbot_internal.automation_definitions(automation_id,deployment_id,tenant_id,owner_id,bot_id,thread_id,current_revision,state)
               VALUES('automation-r','dep','ten','owner','bot-1','automation-thread',1,'enabled');
             INSERT INTO openbot_internal.automation_definition_revisions(deployment_id,tenant_id,automation_id,revision,config_snapshot)
               VALUES('dep','ten','automation-r',1,'{{}}');
             INSERT INTO public.credentials(id,kind,provider,encrypted_value,key_id,metadata) VALUES('{credential}','agent','automation_receiver','{sealed}','receiver-r','{{}}');
             INSERT INTO openbot_internal.automation_receivers(receiver_id,deployment_id,tenant_id,automation_id,adapter,source_principal,event_filter,current_key_revision,vault_record_ref)
               VALUES('receiver-r','dep','ten','automation-r','sender_key','{{\"kind\":\"sender_key\",\"receiverId\":\"receiver-r\"}}','{{\"eventTypes\":[\"push\"],\"matches\":[]}}',1,'{credential}');"
        );
        let restored = RestoreCurrentFixture::publish(&seed, async |_| {}).await;
        let automations = super::PostgresAutomations::new(
            restored.pool.clone(),
            DeploymentId::new("dep"),
            TenantId::new("ten"),
            SecretBytes::new(vec![0x51; 32]),
            vault.clone(),
            restored.read_gate(),
        )
        .unwrap();
        let receiver = AutomationReceiverId::try_from("receiver-r".to_owned()).unwrap();
        let key = SecretBytes::new(b"restored-sender-key".to_vec());

        let opens = vault.open_calls();
        assert_eq!(
            automations.authenticate(&receiver, &key).await.err(),
            Some(AppError::AutomationSourceUnauthorized)
        );
        assert_eq!(vault.open_calls(), opens, "an unconfirmed key was opened");

        let row = restored.pool.get().await.unwrap().query_one(
            "SELECT requirement_id,owner_id FROM openbot_internal.restore_reconfirm_requirements
             WHERE source_kind='credential' AND source_ref=$1 AND owner_kind='service'",
            &[&credential.to_string()],
        ).await.unwrap();
        restored
            .confirm(row.get(0), row.get(1), "fresh_service_operator")
            .await;
        assert_eq!(
            automations
                .authenticate(&receiver, &key)
                .await
                .unwrap()
                .get(),
            1
        );
        assert_eq!(vault.open_calls(), opens + 1);
    }
}
