//! deployment-owned IdP 的 PostgreSQL/vault 原子存储。

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use openbot_contracts::ids::ActorId;
use openbot_domain::audit::event::{AuditEvent, AuditEventType};
use openbot_domain::audit::payload::{AuditIdentifier, AuditLabel, AuditPayload};
use openbot_domain::vault::SecretBytes;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::config::{
    DecodedSecretConfig, RegisteredIdentityProvider, RegistrationPlan, SsoConfigError, SsoProtocol,
    decode_legacy, decode_v2, domains_column, domains_from_column, encode_decoded, encode_plan,
    validate_saml_entity_id, validated_issuer,
};
use super::vault::{SsoConfigVault, SsoSecretColumn, SsoVaultError};
use crate::auth::oidc::{EmailDomain, ProviderId};
use crate::repo::audit::{append_event_in_transaction, next_event_coordinates};
use crate::repo::people_admin::{advance_generation, lock_people};

const SSO_CHANGE_LOCK_KEY: i64 = 0x4f50_5353_4f43_4831; // `OPSSOCH1`

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DynamicSsoStoreError {
    #[error("dynamic_sso_dependency_unavailable")]
    DependencyUnavailable,
    #[error("dynamic_sso_state_corrupt")]
    Corrupt,
    #[error("dynamic_sso_provider_conflict")]
    ProviderConflict,
    #[error("dynamic_sso_domain_conflict")]
    DomainConflict,
    #[error("dynamic_sso_provider_unknown")]
    ProviderUnknown,
    #[error("dynamic_sso_vault_unavailable")]
    VaultUnavailable,
}

impl From<SsoConfigError> for DynamicSsoStoreError {
    fn from(_: SsoConfigError) -> Self {
        Self::Corrupt
    }
}

impl From<SsoVaultError> for DynamicSsoStoreError {
    fn from(_: SsoVaultError) -> Self {
        Self::VaultUnavailable
    }
}

pub(crate) struct LoadedDynamicProvider {
    // Actual locked row incarnation, not a digest, epoch or use grant.
    pub internal_id: Uuid,
    pub provider_id: ProviderId,
    pub issuer: String,
    pub domains: BTreeSet<EmailDomain>,
    pub registered_by: Option<String>,
    pub config: DecodedSecretConfig,
}

impl core::fmt::Debug for LoadedDynamicProvider {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LoadedDynamicProvider")
            .field("internal_id", &self.internal_id)
            .field("provider_id", &self.provider_id)
            .field("issuer", &self.issuer)
            .field("domains", &self.domains)
            .field("registered_by", &self.registered_by)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct DynamicSsoStore {
    pool: Pool,
    vault: SsoConfigVault,
    audit_key: Arc<SecretBytes>,
    reserved_provider_ids: Arc<BTreeSet<String>>,
    configured_environment_provider_ids: Arc<BTreeSet<String>>,
}

/// A non-Serde read capability issued by the actual SSO service. It never migrates or probes.
#[derive(Clone)]
pub struct ReadOnlySsoCapabilitySource {
    pub(super) store: DynamicSsoStore,
}

impl ReadOnlySsoCapabilitySource {
    #[must_use]
    pub fn matches_pool_scope(&self, pool: &Pool) -> bool {
        std::ptr::eq(self.store.pool.manager(), pool.manager())
    }
    pub(crate) fn matches_tenant(&self, tenant: &openbot_contracts::ids::TenantId) -> bool {
        self.store.vault.matches_tenant(tenant)
    }

    pub(crate) fn observe_rows(
        &self,
        rows: &serde_json::Value,
    ) -> openbot_domain::runtime_capabilities::ConfigFact {
        use openbot_domain::runtime_capabilities::ConfigFact;
        let Some(rows) = rows.as_array() else {
            return ConfigFact::Unknown;
        };
        if rows.len() > 256 || self.store.configured_environment_provider_ids.len() > 256 {
            return ConfigFact::Unknown;
        }
        let mut present = !self.store.configured_environment_provider_ids.is_empty();
        let mut invalid = false;
        for row in rows {
            if row.get("bounded").and_then(serde_json::Value::as_bool) != Some(true) {
                return ConfigFact::Unknown;
            }
            let Some(provider) = row.get("provider_id").and_then(serde_json::Value::as_str) else {
                return ConfigFact::Unknown;
            };
            let Some(issuer) = row.get("issuer").and_then(serde_json::Value::as_str) else {
                return ConfigFact::Unknown;
            };
            let Some(domain) = row.get("domain").and_then(serde_json::Value::as_str) else {
                return ConfigFact::Unknown;
            };
            if self.store.stored_provider_id(provider).is_err()
                || domains_from_column(domain).is_err()
                || !row
                    .get("organization_id")
                    .is_some_and(serde_json::Value::is_null)
            {
                invalid = true;
                continue;
            }
            let oidc = row.get("oidc_config").and_then(serde_json::Value::as_str);
            let saml = row.get("saml_config").and_then(serde_json::Value::as_str);
            let (column, stored) = match (oidc, saml) {
                (Some(value), None) if validated_issuer(issuer).is_ok() => {
                    (SsoSecretColumn::Oidc, value)
                }
                (None, Some(value)) if validate_saml_entity_id(issuer).is_ok() => {
                    (SsoSecretColumn::Saml, value)
                }
                _ => {
                    invalid = true;
                    continue;
                }
            };
            let Ok(opened) = self.store.vault.open(provider, column, stored.to_owned()) else {
                return ConfigFact::Unknown;
            };
            // Legacy plaintext/envelopes need the write migration path; GET cannot prove them live.
            if opened.needs_migration {
                return ConfigFact::Unknown;
            }
            let Ok(config) = decode_v2(&opened.plaintext) else {
                invalid = true;
                continue;
            };
            if super::config::validate_readonly_config(column, &config).is_err() {
                invalid = true;
                continue;
            }
            present = true;
        }
        if present {
            ConfigFact::Present
        } else if invalid {
            ConfigFact::Invalid
        } else {
            ConfigFact::Missing
        }
    }
}

impl DynamicSsoStore {
    pub(crate) fn new(
        pool: Pool,
        vault: SsoConfigVault,
        audit_key: impl Into<Vec<u8>>,
        environment_provider_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, DynamicSsoStoreError> {
        let audit_key = audit_key.into();
        if audit_key.is_empty() {
            return Err(DynamicSsoStoreError::Corrupt);
        }
        let mut reserved_provider_ids: BTreeSet<String> =
            environment_provider_ids.into_iter().collect();
        let configured_environment_provider_ids = Arc::new(reserved_provider_ids.clone());
        reserved_provider_ids.extend(
            ["credential", "email-password", "anonymous", "sso"]
                .into_iter()
                .map(str::to_owned),
        );
        Ok(Self {
            pool,
            vault,
            audit_key: Arc::new(SecretBytes::new(audit_key)),
            reserved_provider_ids: Arc::new(reserved_provider_ids),
            configured_environment_provider_ids,
        })
    }

    pub(crate) async fn list(
        &self,
    ) -> Result<Vec<RegisteredIdentityProvider>, DynamicSsoStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let rows = client
            .query(
                "SELECT provider_id,issuer,domain,user_id,organization_id,oidc_config IS NOT NULL AS has_oidc, \
                        saml_config IS NOT NULL AS has_saml \
                 FROM public.sso_providers ORDER BY domain,provider_id",
                &[],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let providers = rows
            .iter()
            .map(|row| {
                let projection = public_projection(row)?;
                self.stored_provider_id(&projection.provider_id)?;
                Ok(projection)
            })
            .collect::<Result<Vec<_>, DynamicSsoStoreError>>()?;
        let mut claimed_domains = BTreeSet::new();
        for provider in &providers {
            for domain in domains_from_column(&provider.domain)? {
                if !claimed_domains.insert(domain) {
                    return Err(DynamicSsoStoreError::Corrupt);
                }
            }
        }
        Ok(providers)
    }

    pub(crate) async fn find_provider_for_domain(
        &self,
        domain: &EmailDomain,
    ) -> Result<Option<ProviderId>, DynamicSsoStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let rows = client
            .query(
                "SELECT provider_id,domain,organization_id FROM public.sso_providers ORDER BY provider_id",
                &[],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let mut matched = None;
        for row in rows {
            assert_deployment_owned_row(&row)?;
            let provider_raw: String = get(&row, "provider_id")?;
            let provider = self.stored_provider_id(&provider_raw)?;
            let stored_domains = domains_from_column(&get::<String>(&row, "domain")?)?;
            if stored_domains.contains(domain) && matched.replace(provider).is_some() {
                return Err(DynamicSsoStoreError::Corrupt);
            }
        }
        Ok(matched)
    }

    pub(crate) async fn load(
        &self,
        provider: &ProviderId,
    ) -> Result<Option<LoadedDynamicProvider>, DynamicSsoStoreError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let row = transaction
            .query_opt(
                "SELECT id,provider_id,issuer,domain,user_id,organization_id,oidc_config,saml_config \
                 FROM public.sso_providers WHERE provider_id=$1 FOR UPDATE",
                &[&provider.as_str()],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
            return Ok(None);
        };
        let loaded = self.load_locked(&transaction, &row).await?;
        transaction
            .commit()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        Ok(Some(loaded))
    }

    pub(crate) async fn register(
        &self,
        plan: &RegistrationPlan,
        actor: &ActorId,
    ) -> Result<RegisteredIdentityProvider, DynamicSsoStoreError> {
        self.write(plan, actor, false).await
    }

    pub(crate) async fn update(
        &self,
        plan: &RegistrationPlan,
        actor: &ActorId,
    ) -> Result<RegisteredIdentityProvider, DynamicSsoStoreError> {
        self.write(plan, actor, true).await
    }

    async fn write(
        &self,
        plan: &RegistrationPlan,
        actor: &ActorId,
        update: bool,
    ) -> Result<RegisteredIdentityProvider, DynamicSsoStoreError> {
        if self
            .reserved_provider_ids
            .contains(plan.provider_id().as_str())
        {
            return Err(DynamicSsoStoreError::ProviderConflict);
        }
        let plaintext = encode_plan(plan)?;
        let column = match plan.protocol() {
            SsoProtocol::Oidc => SsoSecretColumn::Oidc,
            SsoProtocol::Saml => SsoSecretColumn::Saml,
        };
        let encrypted = self
            .vault
            .seal(plan.provider_id().as_str(), column, &plaintext)?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        lock_people(&transaction)
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        lock_sso(&transaction).await?;
        let existing = transaction
            .query_opt(
                "SELECT id,user_id,organization_id FROM public.sso_providers \
                 WHERE provider_id=$1 FOR UPDATE",
                &[&plan.provider_id().as_str()],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        if update != existing.is_some() {
            return Err(if update {
                DynamicSsoStoreError::ProviderUnknown
            } else {
                DynamicSsoStoreError::ProviderConflict
            });
        }
        if let Some(row) = existing.as_ref() {
            assert_deployment_owned_row(row)?;
        }
        let existing_registered_by = existing
            .as_ref()
            .map(|row| row.try_get::<_, Option<String>>("user_id"))
            .transpose()
            .map_err(|_| DynamicSsoStoreError::Corrupt)?;
        assert_domains_available(&transaction, plan.provider_id(), plan.domains()).await?;
        let domain = domains_column(plan.domains());
        let issuer = plan.issuer_str();
        let (oidc_config, saml_config) = match column {
            SsoSecretColumn::Oidc => (Some(encrypted), None),
            SsoSecretColumn::Saml => (None, Some(encrypted)),
        };
        if update {
            let prior_id: String = get(
                existing.as_ref().ok_or(DynamicSsoStoreError::ProviderUnknown)?,
                "id",
            )?;
            let replacement_id = Uuid::now_v7().to_string();
            if replacement_id == prior_id {
                return Err(DynamicSsoStoreError::DependencyUnavailable);
            }
            revoke_linked_accounts(&transaction, plan.provider_id()).await?;
            let updated = transaction
                .query_one(
                    "UPDATE public.sso_providers SET issuer=$2,domain=$3,oidc_config=$4,saml_config=$5,id=$6 \
                     WHERE provider_id=$1 AND id=$7 RETURNING id",
                    &[
                        &plan.provider_id().as_str(),
                        &issuer,
                        &domain,
                        &oidc_config,
                        &saml_config,
                        &replacement_id,
                        &prior_id,
                    ],
                )
                .await
                .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
            if get::<String>(&updated, "id")? != replacement_id {
                return Err(DynamicSsoStoreError::Corrupt);
            }
        } else {
            let id = Uuid::now_v7().to_string();
            transaction
                .execute(
                    "INSERT INTO public.sso_providers( \
                       id,issuer,oidc_config,saml_config,user_id,provider_id,organization_id,domain) \
                     VALUES($1,$2,$3,$4,$5,$6,NULL,$7)",
                    &[
                        &id,
                        &issuer,
                        &oidc_config,
                        &saml_config,
                        &actor.as_str(),
                        &plan.provider_id().as_str(),
                        &domain,
                    ],
                )
                .await
                .map_err(map_provider_write_error)?;
        }
        append_idp_audit(
            &transaction,
            actor,
            plan.provider_id(),
            if update {
                "configuration.changed"
            } else {
                "identity_provider.registered"
            },
            self.audit_key.expose(),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        Ok(RegisteredIdentityProvider {
            provider_id: plan.provider_id().as_str().to_owned(),
            issuer: issuer.to_owned(),
            domain,
            protocol: plan.protocol(),
            registered_by: if update {
                existing_registered_by.flatten()
            } else {
                Some(actor.as_str().to_owned())
            },
        })
    }

    pub(crate) async fn remove(
        &self,
        provider: &ProviderId,
        actor: &ActorId,
    ) -> Result<(), DynamicSsoStoreError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        lock_people(&transaction)
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        lock_sso(&transaction).await?;
        let exists = transaction
            .query_opt(
                "SELECT id FROM public.sso_providers WHERE provider_id=$1 FOR UPDATE",
                &[&provider.as_str()],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        if exists.is_none() {
            return Err(DynamicSsoStoreError::ProviderUnknown);
        }
        // 删除 provider id 前先删 account anchors；否则重注册同 id 可继承旧受害者链接。
        revoke_linked_accounts(&transaction, provider).await?;
        transaction
            .execute(
                "DELETE FROM public.sso_providers WHERE provider_id=$1",
                &[&provider.as_str()],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        append_idp_audit(
            &transaction,
            actor,
            provider,
            "identity_provider.removed",
            self.audit_key.expose(),
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)
    }

    async fn load_locked(
        &self,
        transaction: &Transaction<'_>,
        row: &Row,
    ) -> Result<LoadedDynamicProvider, DynamicSsoStoreError> {
        let internal_raw: String = get(row, "id")?;
        let internal_id = Uuid::parse_str(&internal_raw)
            .map_err(|_| DynamicSsoStoreError::Corrupt)?;
        if internal_id.is_nil() || internal_id.to_string() != internal_raw {
            return Err(DynamicSsoStoreError::Corrupt);
        }
        let provider_raw: String = get(row, "provider_id")?;
        let provider_id = self.stored_provider_id(&provider_raw)?;
        assert_deployment_owned_row(row)?;
        let issuer_raw: String = get(row, "issuer")?;
        let domain_raw: String = get(row, "domain")?;
        let domains = domains_from_column(&domain_raw)?;
        let canonical_domain = domains_column(&domains);
        if canonical_domain != domain_raw {
            transaction
                .execute(
                    "UPDATE public.sso_providers SET domain=$2 WHERE provider_id=$1",
                    &[&provider_id.as_str(), &canonical_domain],
                )
                .await
                .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        }
        let registered_by: Option<String> = get(row, "user_id")?;
        let oidc: Option<String> = get(row, "oidc_config")?;
        let saml: Option<String> = get(row, "saml_config")?;
        let (column, stored) = match (oidc, saml) {
            (Some(value), None) => (SsoSecretColumn::Oidc, value),
            (None, Some(value)) => (SsoSecretColumn::Saml, value),
            _ => return Err(DynamicSsoStoreError::Corrupt),
        };
        match column {
            SsoSecretColumn::Oidc => {
                validated_issuer(&issuer_raw)?;
            }
            SsoSecretColumn::Saml => validate_saml_entity_id(&issuer_raw)?,
        }
        let opened = self.vault.open(provider_id.as_str(), column, stored)?;
        let config = match decode_v2(&opened.plaintext) {
            Ok(config) => config,
            Err(_) => decode_legacy(column, &opened.plaintext, &issuer_raw)?,
        };
        if opened.needs_migration || decode_v2(&opened.plaintext).is_err() {
            let canonical = encode_decoded(&config)?;
            let encrypted = self.vault.seal(provider_id.as_str(), column, &canonical)?;
            let sql = match column {
                SsoSecretColumn::Oidc => {
                    "UPDATE public.sso_providers SET oidc_config=$2 WHERE provider_id=$1"
                }
                SsoSecretColumn::Saml => {
                    "UPDATE public.sso_providers SET saml_config=$2 WHERE provider_id=$1"
                }
            };
            transaction
                .execute(sql, &[&provider_id.as_str(), &encrypted])
                .await
                .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
            let readback: String = transaction
                .query_one(
                    match column {
                        SsoSecretColumn::Oidc => {
                            "SELECT oidc_config FROM public.sso_providers WHERE provider_id=$1"
                        }
                        SsoSecretColumn::Saml => {
                            "SELECT saml_config FROM public.sso_providers WHERE provider_id=$1"
                        }
                    },
                    &[&provider_id.as_str()],
                )
                .await
                .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?
                .try_get(0)
                .map_err(|_| DynamicSsoStoreError::Corrupt)?;
            let verified = self.vault.open(provider_id.as_str(), column, readback)?;
            if !verified.plaintext.ct_eq(&canonical) {
                return Err(DynamicSsoStoreError::VaultUnavailable);
            }
        }
        Ok(LoadedDynamicProvider {
            internal_id,
            provider_id,
            issuer: issuer_raw,
            domains,
            registered_by,
            config,
        })
    }

    fn stored_provider_id(&self, raw: &str) -> Result<ProviderId, DynamicSsoStoreError> {
        let provider = ProviderId::parse(raw).map_err(|_| DynamicSsoStoreError::Corrupt)?;
        if self.reserved_provider_ids.contains(provider.as_str()) {
            return Err(DynamicSsoStoreError::Corrupt);
        }
        Ok(provider)
    }
}

impl core::fmt::Debug for DynamicSsoStore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DynamicSsoStore")
            .field("vault", &self.vault)
            .field("audit_key", &"[REDACTED]")
            .field("reserved_provider_ids", &self.reserved_provider_ids)
            .finish_non_exhaustive()
    }
}

async fn lock_sso(transaction: &Transaction<'_>) -> Result<(), DynamicSsoStoreError> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&SSO_CHANGE_LOCK_KEY])
        .await
        .map(|_| ())
        .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)
}

async fn assert_domains_available(
    transaction: &Transaction<'_>,
    provider: &ProviderId,
    proposed: &BTreeSet<EmailDomain>,
) -> Result<(), DynamicSsoStoreError> {
    let rows = transaction
        .query(
            "SELECT provider_id,domain FROM public.sso_providers WHERE provider_id<>$1 FOR UPDATE",
            &[&provider.as_str()],
        )
        .await
        .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
    for row in rows {
        let existing: String = row
            .try_get("domain")
            .map_err(|_| DynamicSsoStoreError::Corrupt)?;
        let existing = domains_from_column(&existing)?;
        if !existing.is_disjoint(proposed) {
            return Err(DynamicSsoStoreError::DomainConflict);
        }
    }
    Ok(())
}

async fn revoke_linked_accounts(
    transaction: &Transaction<'_>,
    provider: &ProviderId,
) -> Result<(), DynamicSsoStoreError> {
    let rows = transaction
        .query(
            "SELECT user_id FROM public.accounts WHERE provider_id=$1 FOR UPDATE",
            &[&provider.as_str()],
        )
        .await
        .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
    let actors = rows
        .iter()
        .map(|row| {
            row.try_get::<_, String>(0)
                .map_err(|_| DynamicSsoStoreError::Corrupt)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for actor in actors {
        let actor = ActorId::new(actor);
        advance_generation(transaction, &actor, None)
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
        transaction
            .execute(
                "DELETE FROM public.sessions WHERE user_id=$1",
                &[&actor.as_str()],
            )
            .await
            .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
    }
    transaction
        .execute(
            "DELETE FROM public.accounts WHERE provider_id=$1",
            &[&provider.as_str()],
        )
        .await
        .map(|_| ())
        .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)
}

async fn append_idp_audit(
    transaction: &Transaction<'_>,
    actor: &ActorId,
    provider: &ProviderId,
    event_type: &'static str,
    key: &[u8],
) -> Result<(), DynamicSsoStoreError> {
    let event_type = AuditEventType::parse(event_type).ok_or(DynamicSsoStoreError::Corrupt)?;
    let (id, created_at) = next_event_coordinates(transaction)
        .await
        .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)?;
    let target_id =
        AuditIdentifier::new(provider.as_str()).map_err(|_| DynamicSsoStoreError::Corrupt)?;
    append_event_in_transaction(
        transaction,
        &AuditEvent {
            id,
            actor: Some(actor.clone()),
            event_type,
            target_kind: AuditLabel::new("identity_provider"),
            target_id: Some(target_id),
            payload: AuditPayload::empty(),
            created_at,
        },
        key,
    )
    .await
    .map(|_| ())
    .map_err(|_| DynamicSsoStoreError::DependencyUnavailable)
}

fn public_projection(row: &Row) -> Result<RegisteredIdentityProvider, DynamicSsoStoreError> {
    assert_deployment_owned_row(row)?;
    let has_oidc: bool = get(row, "has_oidc")?;
    let has_saml: bool = get(row, "has_saml")?;
    let protocol = match (has_oidc, has_saml) {
        (true, false) => SsoProtocol::Oidc,
        (false, true) => SsoProtocol::Saml,
        _ => return Err(DynamicSsoStoreError::Corrupt),
    };
    let provider_id: String = get(row, "provider_id")?;
    ProviderId::parse(&provider_id).map_err(|_| DynamicSsoStoreError::Corrupt)?;
    let issuer: String = get(row, "issuer")?;
    match protocol {
        SsoProtocol::Oidc => {
            validated_issuer(&issuer)?;
        }
        SsoProtocol::Saml => validate_saml_entity_id(&issuer)?,
    }
    let domain: String = get(row, "domain")?;
    let domains = domains_from_column(&domain)?;
    Ok(RegisteredIdentityProvider {
        provider_id,
        issuer,
        domain: domains_column(&domains),
        protocol,
        registered_by: get(row, "user_id")?,
    })
}

fn assert_deployment_owned_row(row: &Row) -> Result<(), DynamicSsoStoreError> {
    let organization_id: Option<String> = get(row, "organization_id")?;
    if organization_id.is_some() {
        Err(DynamicSsoStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn get<'row, T>(row: &'row Row, column: &'static str) -> Result<T, DynamicSsoStoreError>
where
    T: tokio_postgres::types::FromSql<'row>,
{
    row.try_get(column)
        .map_err(|_| DynamicSsoStoreError::Corrupt)
}

fn map_provider_write_error(error: tokio_postgres::Error) -> DynamicSsoStoreError {
    match error.code() {
        Some(code) if *code == tokio_postgres::error::SqlState::UNIQUE_VIOLATION => {
            DynamicSsoStoreError::ProviderConflict
        }
        _ => DynamicSsoStoreError::DependencyUnavailable,
    }
}
