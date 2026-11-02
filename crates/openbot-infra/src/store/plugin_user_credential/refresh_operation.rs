//! Durable OAuth send ownership. Reading an operation never grants permission to send it again.

use std::sync::atomic::{AtomicU8, Ordering};
use tokio_postgres::Transaction;

use super::*;

pub(super) struct RefreshOperation {
    id: Uuid,
    generation: i64,
}

#[async_trait]
pub(super) trait RefreshSendFence: Send + Sync {
    async fn admit(&self) -> Result<(), OAuthTokenExchangeError>;
}

pub(super) struct OperationSendFence<'a> {
    store: &'a PluginUserCredentialStore,
    prepared: &'a PreparedUserOAuthCredential,
    operation: &'a RefreshOperation,
    admission: &'a RecoveryWorkerLease<'a>,
    // 0=new, 1=claim in progress, 2=durably admitted, 3=refused/uncertain. Never reset.
    state: AtomicU8,
}

impl<'a> OperationSendFence<'a> {
    pub(super) fn new(
        store: &'a PluginUserCredentialStore,
        prepared: &'a PreparedUserOAuthCredential,
        operation: &'a RefreshOperation,
        admission: &'a RecoveryWorkerLease<'a>,
    ) -> Self {
        Self {
            store,
            prepared,
            operation,
            admission,
            state: AtomicU8::new(0),
        }
    }

    pub(super) fn admitted(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }
}

#[async_trait]
impl RefreshSendFence for OperationSendFence<'_> {
    async fn admit(&self) -> Result<(), OAuthTokenExchangeError> {
        self.state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| OAuthTokenExchangeError::Unavailable)?;
        // The held admission is rechecked at the durable send admission, which
        // the adapter reaches immediately before its token POST.
        let result = match current(self.admission) {
            Ok(()) => {
                self.store
                    .admit_refresh(self.prepared, self.operation)
                    .await
            }
            Err(error) => Err(error),
        };
        self.state
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Release);
        result.map_err(|_| OAuthTokenExchangeError::Unavailable)
    }
}

impl PluginUserCredentialStore {
    pub(super) async fn claim_refresh(
        &self,
        prepared: &PreparedUserOAuthCredential,
    ) -> Result<RefreshOperation, UserCredentialSelectionError> {
        if self.rotation_checkpoint_key.is_none() {
            return Err(UserCredentialSelectionError::Corrupt {
                field: "audit_checkpoint_key",
            });
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        lock_binding(
            &tx,
            prepared,
            &prepared.user_encrypted_value,
            &prepared.scope,
        )
        .await?;
        if let Some(row) = tx.query_opt(
            "SELECT state FROM public.oauth_refresh_operations WHERE credential_id=$1 AND state<>'committed'",
            &[&prepared.user_credential_id],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)? {
            let state: String = row.get(0);
            return Err(if state == "auth_required" {
                UserCredentialRefusal::ReconnectRequired.into()
            } else { UserCredentialSelectionError::RotationPending });
        }
        let previous: i64 = tx.query_one(
            "SELECT coalesce(max(generation),0)::bigint FROM public.oauth_refresh_operations WHERE credential_id=$1",
            &[&prepared.user_credential_id],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?.get(0);
        let operation = RefreshOperation {
            id: Uuid::now_v7(),
            generation: previous
                .checked_add(1)
                .ok_or(UserCredentialSelectionError::Corrupt {
                    field: "refresh_generation",
                })?,
        };
        tx.execute(
            "INSERT INTO public.oauth_refresh_operations(operation_id,credential_id,generation,actor_id,auth_generation,server_id,client_credential_id,server_generation,server_updated_at,client_updated_at,resource,transport,egress_allow_cidrs,granted_scope,state,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'pending',clock_timestamp())",
            &[&operation.id,&prepared.user_credential_id,&operation.generation,&prepared.actor.as_str(),&prepared.auth_generation,&prepared.server_id,&prepared.deployment_credential_id,&prepared.server_generation,&prepared.server_updated_at,&prepared.client_updated_at,&prepared.endpoint,&prepared.transport,&prepared.egress_allow_cidrs,&prepared.scope],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| UserCredentialSelectionError::CommitUnknown)?;
        Ok(operation)
    }

    async fn admit_refresh(
        &self,
        prepared: &PreparedUserOAuthCredential,
        operation: &RefreshOperation,
    ) -> Result<(), UserCredentialSelectionError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        lock_binding(
            &tx,
            prepared,
            &prepared.user_encrypted_value,
            &prepared.scope,
        )
        .await?;
        let changed = tx.execute(
            "UPDATE public.oauth_refresh_operations SET admitted_at=clock_timestamp() WHERE operation_id=$1 AND credential_id=$2 AND generation=$3 AND state='pending' AND admitted_at IS NULL",
            &[&operation.id,&prepared.user_credential_id,&operation.generation],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
        if changed != 1 {
            return Err(UserCredentialSelectionError::RotationPending);
        }
        tx.commit()
            .await
            .map_err(|_| UserCredentialSelectionError::CommitUnknown)
    }

    pub(super) async fn fail_refresh(&self, operation: &RefreshOperation, auth_required: bool) {
        // Best effort: if PostgreSQL is unreachable, the original pending row still blocks reuse.
        if let Ok(client) = self.pool.get().await {
            let state = if auth_required {
                "auth_required"
            } else {
                "unknown"
            };
            let _ = client.execute(
                "UPDATE public.oauth_refresh_operations SET state=$2,completed_at=clock_timestamp() WHERE operation_id=$1 AND state='pending' AND admitted_at IS NOT NULL",
                &[&operation.id,&state],
            ).await;
        }
    }

    pub(super) async fn finish_refresh(
        &self,
        prepared: &PreparedUserOAuthCredential,
        operation: &RefreshOperation,
        refresh_token: Option<SecretBytes>,
        scope: Option<String>,
    ) -> Result<(), UserCredentialSelectionError> {
        let checkpoint_key =
            self.rotation_checkpoint_key
                .as_ref()
                .ok_or(UserCredentialSelectionError::Corrupt {
                    field: "audit_checkpoint_key",
                })?;
        let scope = scope.unwrap_or_else(|| prepared.scope.clone());
        if scope.len() > 16 * 1024 || scope.as_bytes().contains(&0) {
            return Err(UserCredentialSelectionError::Corrupt { field: "scope" });
        }
        let encrypted = refresh_token
            .as_ref()
            .map(|secret| {
                self.vault.seal(
                    &prepared.user_credential_id,
                    SecretKind::McpUserToken,
                    SecretPrincipal::Actor(prepared.actor.clone()),
                    SecretPrincipal::Service(ServiceId::new(&prepared.server_id)),
                    secret,
                )
            })
            .transpose()
            .map_err(|_| UserCredentialSelectionError::Corrupt {
                field: "rotated_refresh_token",
            })?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        lock_binding(
            &tx,
            prepared,
            &prepared.user_encrypted_value,
            &prepared.scope,
        )
        .await?;
        let pending = tx.query_opt(
            "SELECT operation_id FROM public.oauth_refresh_operations WHERE operation_id=$1 AND credential_id=$2 AND generation=$3 AND state='pending' AND admitted_at IS NOT NULL FOR UPDATE",
            &[&operation.id,&prepared.user_credential_id,&operation.generation],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
        if pending.is_none() {
            return Err(UserCredentialSelectionError::RotationPending);
        }
        if let Some(encrypted) = &encrypted {
            let changed = tx.execute(
                "UPDATE public.credentials SET encrypted_value=$3,metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('server',$4::text,'scope',$5::text,'rotation','oauth_refresh'),updated_at=clock_timestamp() WHERE id=$1 AND encrypted_value=$2 AND revoked_at IS NULL",
                &[&prepared.user_credential_id,&prepared.user_encrypted_value,encrypted,&prepared.server_id,&scope],
            ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
            if changed != 1 {
                return Err(UserCredentialSelectionError::Conflict);
            }
        }
        let changed = tx.execute(
            "UPDATE public.mcp_user_credentials SET scope=$4,updated_at=clock_timestamp() WHERE server_id=$1 AND user_id=$2 AND credential_id=$3",
            &[&prepared.server_id,&prepared.actor.as_str(),&prepared.user_credential_id,&scope],
        ).await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
        if changed != 1 {
            return Err(UserCredentialSelectionError::Conflict);
        }
        let (id, created_at) = next_event_coordinates(&tx)
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        let event = AuditEvent {
            id,
            actor: Some(prepared.actor.clone()),
            event_type: AuditEventType::parse(if encrypted.is_some() {
                "credential.rotated"
            } else {
                "mcp.token_refreshed"
            })
            .ok_or(UserCredentialSelectionError::Corrupt {
                field: "audit_event_type",
            })?,
            target_kind: AuditLabel::new("credential"),
            target_id: Some(
                AuditIdentifier::new(prepared.user_credential_id.to_string()).map_err(|_| {
                    UserCredentialSelectionError::Corrupt {
                        field: "credential_id",
                    }
                })?,
            ),
            payload: AuditPayload::from_facts([
                AuditFact::CredentialOwner(
                    AuditIdentifier::new(prepared.actor.as_str())
                        .map_err(|_| UserCredentialSelectionError::Corrupt { field: "actor_id" })?,
                ),
                AuditFact::RevocationReason(AuditLabel::new(if encrypted.is_some() {
                    "oauth_refresh_rotation"
                } else {
                    "oauth_access_refresh"
                })),
            ])
            .map_err(|_| UserCredentialSelectionError::Corrupt {
                field: "audit_payload",
            })?,
            created_at,
        };
        append_event_in_transaction(&tx, &event, checkpoint_key.expose())
            .await
            .map_err(|_| UserCredentialSelectionError::Unavailable)?;
        tx.execute("UPDATE public.oauth_refresh_operations SET state='committed',completed_at=clock_timestamp() WHERE operation_id=$1", &[&operation.id])
            .await.map_err(|_| UserCredentialSelectionError::Unavailable)?;
        if tx.commit().await.is_ok() {
            return Ok(());
        }
        // Lost COMMIT acknowledgement is resolved only by reading this operation. No token POST.
        drop(client);
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| UserCredentialSelectionError::CommitUnknown)?;
        let tx = client
            .transaction()
            .await
            .map_err(|_| UserCredentialSelectionError::CommitUnknown)?;
        lock_binding(
            &tx,
            prepared,
            encrypted
                .as_deref()
                .unwrap_or(&prepared.user_encrypted_value),
            &scope,
        )
        .await?;
        let committed = tx.query_opt(
            "SELECT operation_id FROM public.oauth_refresh_operations WHERE operation_id=$1 AND credential_id=$2 AND generation=$3 AND state='committed' AND admitted_at IS NOT NULL",
            &[&operation.id,&prepared.user_credential_id,&operation.generation],
        ).await.map_err(|_| UserCredentialSelectionError::CommitUnknown)?.is_some();
        if committed {
            Ok(())
        } else {
            Err(UserCredentialSelectionError::CommitUnknown)
        }
    }
}

async fn lock_binding(
    tx: &Transaction<'_>,
    prepared: &PreparedUserOAuthCredential,
    encrypted: &str,
    scope: &str,
) -> Result<(), UserCredentialSelectionError> {
    let row = tx
        .query_opt(
            "SELECT c.id FROM public.mcp_servers s
         JOIN public.mcp_user_credentials uc ON uc.server_id=s.id AND uc.user_id=$2
         JOIN public.credentials c ON c.id=uc.credential_id
         JOIN public.credentials d ON d.id=s.credential_id
         JOIN public.users owner ON owner.id=uc.user_id
         WHERE s.id=$1 AND c.id=$3 AND c.encrypted_value=$4 AND c.revoked_at IS NULL
           AND c.kind='mcp_user_token' AND c.provider=s.id AND c.key_id=owner.id
           AND d.id=$5 AND d.encrypted_value=$6 AND d.revoked_at IS NULL
           AND d.kind='mcp_oauth_client' AND d.provider=s.id
           AND s.url=$7 AND coalesce(s.transport,'mcp')=$8
           AND coalesce(s.egress_allow_cidrs,ARRAY[]::text[])=$9
           AND coalesce(s.credential_generation,0)=$10 AND s.updated_at=$11 AND d.updated_at=$12
           AND coalesce(owner.auth_generation,0)=$13 AND uc.scope=$14
           AND EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=owner.id)
           AND NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(owner.email))
         FOR SHARE OF owner,s,d,uc FOR UPDATE OF c",
            &[
                &prepared.server_id,
                &prepared.actor.as_str(),
                &prepared.user_credential_id,
                &encrypted,
                &prepared.deployment_credential_id,
                &prepared.client_encrypted_value,
                &prepared.endpoint,
                &prepared.transport,
                &prepared.egress_allow_cidrs,
                &prepared.server_generation,
                &prepared.server_updated_at,
                &prepared.client_updated_at,
                &prepared.auth_generation,
                &scope,
            ],
        )
        .await
        .map_err(|_| UserCredentialSelectionError::Unavailable)?;
    row.map(|_| ())
        .ok_or(UserCredentialSelectionError::Conflict)
}
