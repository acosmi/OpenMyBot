//! Trusted startup adoption of the immutable artifact dataset namespace.
//!
//! Dataset identity is a storage fact. Neither these values nor a source observation grants
//! permission to save or read artifact bytes. Actual records, byte roots and producers follow
//! separately. Each adapter retains the pool that produced its private binding.

use std::sync::Arc;

use crate::db::pool::DatabasePool as Pool;
use openbot_contracts::artifacts::is_valid_artifact_identity;
use openbot_contracts::ids::{DeploymentId, TenantId};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::{IsolationLevel, Row};

use crate::db::desktop_local::DesktopLocalDatabase;
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
use crate::db::desktop_vault_canary::VerifiedDesktopArtifactReadProvenance;
use crate::db::desktop_vault_canary::VerifiedDesktopVaultCanary;
use crate::db::{native, schema_facts};

/// Ordered, nonsecret PostgreSQL catalog facts for the internal registry and its actual guard.
pub type ArtifactRegistrySchemaFacts = Value;

/// Independent internal-schema extraction. Public `SchemaFacts` does not cover this table.
pub const ARTIFACT_REGISTRY_SCHEMA_SQL: &str = r"
SELECT pg_catalog.jsonb_build_object(
 'relation',(
   SELECT pg_catalog.jsonb_build_object(
     'kind',c.relkind::text,'persistence',c.relpersistence::text,
     'partition',c.relispartition,'rowSecurity',c.relrowsecurity,
     'forceRowSecurity',c.relforcerowsecurity,'accessMethod',am.amname)
   FROM pg_catalog.pg_class c
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
   WHERE n.nspname='openbot_internal' AND c.relname='artifact_dataset_bindings'
 ),
 'columns',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),
     'notNull',a.attnotnull,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid),
     'ordinal',a.attnum,'identity',a.attidentity::text,'generated',a.attgenerated::text,
     'collationSchema',cn.nspname,'collation',co.collname) ORDER BY a.attnum),'[]'::jsonb)
   FROM pg_catalog.pg_attribute a
   LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
   LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
   WHERE a.attrelid=pg_catalog.to_regclass('openbot_internal.artifact_dataset_bindings')
     AND a.attnum>0 AND NOT a.attisdropped
 ),
 'constraints',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',c.conname,'kind',c.contype::text,'validated',c.convalidated,
     'deferrable',c.condeferrable,'deferred',c.condeferred,
     'definition',pg_catalog.pg_get_constraintdef(c.oid)) ORDER BY c.conname),'[]'::jsonb)
   FROM pg_catalog.pg_constraint c
   WHERE c.conrelid=pg_catalog.to_regclass('openbot_internal.artifact_dataset_bindings')
     AND c.contype<>'n'
 ),
 'indexes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',c.relname,'primary',i.indisprimary,'unique',i.indisunique,
     'valid',i.indisvalid,'ready',i.indisready,'keys',i.indkey::text,
     'predicate',pg_catalog.pg_get_expr(i.indpred,i.indrelid),
     'expressions',pg_catalog.pg_get_expr(i.indexprs,i.indrelid),
     'definition',pg_catalog.pg_get_indexdef(i.indexrelid)) ORDER BY c.relname),'[]'::jsonb)
   FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   WHERE i.indrelid=pg_catalog.to_regclass('openbot_internal.artifact_dataset_bindings')
 ),
 'triggers',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'name',t.tgname,'enabled',t.tgenabled::text,'type',t.tgtype::integer,
     'definition',pg_catalog.pg_get_triggerdef(t.oid),
     'functionSchema',n.nspname,'functionName',p.proname,
     'functionArguments',pg_catalog.pg_get_function_identity_arguments(p.oid))
       ORDER BY t.tgname),'[]'::jsonb)
   FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE t.tgrelid=pg_catalog.to_regclass('openbot_internal.artifact_dataset_bindings')
     AND NOT t.tgisinternal
 ),
 'rules',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.pg_get_ruledef(r.oid)
     ORDER BY r.rulename),'[]'::jsonb)
   FROM pg_catalog.pg_rewrite r
   WHERE r.ev_class=pg_catalog.to_regclass('openbot_internal.artifact_dataset_bindings')
 ),
 'guard',(
   SELECT pg_catalog.jsonb_build_object(
     'schema',n.nspname,'name',p.proname,
     'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),
     'language',l.lanname,'securityDefiner',p.prosecdef,'configuration',p.proconfig,
     'returnType',pg_catalog.format_type(p.prorettype,NULL),
     'definition',pg_catalog.pg_get_functiondef(p.oid))
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   WHERE n.nspname='openbot_internal' AND p.proname='prevent_append_only_mutation'
     AND p.pronargs=0
 )
)::text
";

// Independently captured from the owned PostgreSQL fixture, including the actual guard body.
// Current live catalog facts cannot become their own acceptance oracle.
const REGISTERED_INTERNAL_SCHEMA: &str =
    include_str!("../../../fixtures/db/artifact-dataset-bindings-0041.json");
const REGISTERED_PUBLIC_SCHEMA: &str = include_str!("../../../fixtures/db/schema-0052.json");

const READ_NAMESPACE: &str = r"
SELECT
 CASE WHEN octet_length(deployment_id) BETWEEN 1 AND 512
       AND deployment_id !~ U&'[\0001-\001F\007F-\009F]'
      THEN deployment_id END AS deployment_id,
 CASE WHEN octet_length(tenant_id) BETWEEN 1 AND 512
       AND tenant_id !~ U&'[\0001-\001F\007F-\009F]'
      THEN tenant_id END AS tenant_id,
 CASE WHEN octet_length(dataset_id) BETWEEN 1 AND 512
       AND dataset_id !~ U&'[\0001-\001F\007F-\009F]'
      THEN dataset_id END AS dataset_id,
 CASE WHEN binding_schema=1 THEN binding_schema END AS binding_schema,
 CASE WHEN initial_origin IN ('desktop_canary','server_first_adoption')
      THEN initial_origin END AS initial_origin,
 created_at
FROM openbot_internal.artifact_dataset_bindings
WHERE deployment_id=$1 AND tenant_id=$2
";
const INSERT_NAMESPACE: &str = "INSERT INTO openbot_internal.artifact_dataset_bindings \
 (deployment_id,tenant_id,dataset_id,binding_schema,initial_origin) \
 VALUES($1,$2,$3,1,$4) ON CONFLICT(deployment_id,tenant_id) DO NOTHING";

/// Stable failures; no database values, paths or connection details cross this boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactRegistryError {
    /// A trusted startup selector does not satisfy the existing bounded identity shape.
    #[error("artifact_registry_invalid_input")]
    InvalidInput { field: &'static str },
    /// PostgreSQL, cryptographic observation or CSPRNG is unavailable.
    #[error("artifact_registry_unavailable")]
    Unavailable,
    /// Persistent shape or an exact physical tuple differs from the registered fact.
    #[error("artifact_registry_corrupt")]
    Corrupt { field: &'static str },
    /// A current Desktop proof is required to adopt an existing canary namespace.
    #[error("artifact_registry_desktop_proof_required")]
    ProofRequired,
}

/// Opaque current host/PG dataset binding. It cannot be deserialized or freely constructed.
pub struct VerifiedArtifactDatasetBinding {
    deployment_id: String,
    tenant_id: String,
    dataset_id: String,
    binding_schema: i16,
    initial_origin: String,
    created_at: OffsetDateTime,
    // Retain this process owner even in the minimal registry-only Desktop graph.
    _owner: Arc<()>,
}

impl VerifiedArtifactDatasetBinding {
    #[must_use]
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    #[must_use]
    pub fn initial_origin(&self) -> &str {
        &self.initial_origin
    }
    #[must_use]
    pub const fn binding_schema(&self) -> i16 {
        self.binding_schema
    }
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

impl core::fmt::Debug for VerifiedArtifactDatasetBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedArtifactDatasetBinding(<verified>)")
    }
}

/// Internal repository retaining the same pool and the exact immutable startup observation.
pub struct ArtifactDatasetRegistry {
    pool: Pool,
    binding: VerifiedArtifactDatasetBinding,
    #[cfg(all(
        feature = "server-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    desktop_read_provenance: Option<VerifiedDesktopArtifactReadProvenance>,
}

impl core::fmt::Debug for ArtifactDatasetRegistry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ArtifactDatasetRegistry(<verified>)")
    }
}

impl ArtifactDatasetRegistry {
    /// Adopt or read a namespace only from the trusted Server startup composition root.
    pub async fn from_server(
        pool: Pool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> Result<Self, ArtifactRegistryError> {
        validate_namespace(deployment.as_str(), tenant.as_str())?;
        verify_artifact_registry_schema(&pool).await?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        transaction
            .batch_execute(
                "SET LOCAL lock_timeout='5s'; \
                 LOCK TABLE openbot_internal.desktop_vault_canaries IN SHARE MODE",
            )
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let row = transaction
            .query_opt(READ_NAMESPACE, &[&deployment.as_str(), &tenant.as_str()])
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let canary_exists: bool = transaction
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM openbot_internal.desktop_vault_canaries \
                 WHERE deployment_id=$1 AND tenant_id=$2)",
                &[&deployment.as_str(), &tenant.as_str()],
            )
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("canary_shape"))?;
        // This limited Server startup entry has no current Desktop cryptographic proof.
        // Keep even an already-registered canary namespace on its proper Desktop entry.
        if canary_exists {
            return Err(ArtifactRegistryError::ProofRequired);
        }
        if row.is_none() {
            let dataset = mint_dataset()?;
            transaction
                .execute(
                    INSERT_NAMESPACE,
                    &[
                        &deployment.as_str(),
                        &tenant.as_str(),
                        &dataset,
                        &"server_first_adoption",
                    ],
                )
                .await
                .map_err(|_| ArtifactRegistryError::Unavailable)?;
        }
        // A separate RC statement sees a competing INSERT's committed winner. Do not fold this
        // into INSERT DO NOTHING's snapshot, or regard our random candidate as its result.
        let binding = decode_binding(
            transaction
                .query_opt(READ_NAMESPACE, &[&deployment.as_str(), &tenant.as_str()])
                .await
                .map_err(|_| ArtifactRegistryError::Unavailable)?
                .ok_or_else(|| corrupt("dataset_binding"))?,
        )?;
        transaction
            .commit()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        drop(client);
        Ok(Self {
            pool,
            binding,
            #[cfg(all(
                feature = "server-runtime",
                any(target_os = "macos", target_os = "linux")
            ))]
            desktop_read_provenance: None,
        })
    }

    /// Adopt the original dataset only after a current cryptographic same-database proof.
    pub async fn from_desktop(
        database: &DesktopLocalDatabase,
        proof: &VerifiedDesktopVaultCanary,
    ) -> Result<Self, ArtifactRegistryError> {
        validate_namespace(proof.deployment_id(), proof.tenant_id())?;
        if !proof
            .matches_database(database)
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
        {
            return Err(corrupt("desktop_proof"));
        }
        let pool = database.clone_pool();
        verify_artifact_registry_schema(&pool).await?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        transaction
            .batch_execute(
                "SET LOCAL lock_timeout='5s'; \
                 LOCK TABLE openbot_internal.desktop_vault_canaries IN SHARE MODE",
            )
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        if !proof
            .matches_transaction(database, &transaction)
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
        {
            return Err(corrupt("desktop_proof"));
        }
        transaction
            .execute(
                INSERT_NAMESPACE,
                &[
                    &proof.deployment_id(),
                    &proof.tenant_id(),
                    &proof.dataset_id(),
                    &"desktop_canary",
                ],
            )
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let binding = decode_binding(
            transaction
                .query_opt(
                    READ_NAMESPACE,
                    &[&proof.deployment_id(), &proof.tenant_id()],
                )
                .await
                .map_err(|_| ArtifactRegistryError::Unavailable)?
                .ok_or_else(|| corrupt("dataset_binding"))?,
        )?;
        if binding.dataset_id != proof.dataset_id()
            || binding.deployment_id != proof.deployment_id()
            || binding.tenant_id != proof.tenant_id()
        {
            return Err(corrupt("desktop_dataset_binding"));
        }
        // initial_origin is immutable history, even when a later trusted host sees the same tuple.
        transaction
            .commit()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        drop(client);
        if !proof
            .matches_database(database)
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
        {
            return Err(corrupt("desktop_proof"));
        }
        Ok(Self {
            pool,
            binding,
            #[cfg(all(
                feature = "server-runtime",
                any(target_os = "macos", target_os = "linux")
            ))]
            desktop_read_provenance: Some(proof.artifact_read_provenance()),
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &VerifiedArtifactDatasetBinding {
        &self.binding
    }

    /// Composition provenance for pool clones; it does not attest a cluster or grant user rights.
    #[must_use]
    pub fn matches_pool_scope(
        &self,
        pool: &Pool,
        deployment: &DeploymentId,
        tenant: &TenantId,
    ) -> bool {
        std::ptr::eq(self.pool.manager(), pool.manager())
            && self.binding.deployment_id == deployment.as_str()
            && self.binding.tenant_id == tenant.as_str()
    }

    /// Genuine Desktop adoption is required; historical initial_origin is insufficient.
    #[cfg(all(
        feature = "server-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    #[must_use]
    pub(crate) fn matches_desktop_read_installation(
        &self,
        installation: &crate::auth::single_user::desktop_local::DesktopLocalAuthority,
    ) -> bool {
        self.desktop_read_provenance.as_ref().is_some_and(|proof| {
            proof.matches_installation(installation)
                && self.binding.deployment_id == installation.auth_context().deployment().as_str()
                && self.binding.tenant_id == installation.auth_context().tenant().as_str()
        })
    }

    /// Compare the actual final joint statement with the original cryptographic tuple/digest.
    #[cfg(all(
        feature = "server-runtime",
        any(target_os = "macos", target_os = "linux")
    ))]
    pub(crate) fn matches_desktop_read_current_row(
        &self,
        row: &Row,
    ) -> Result<bool, ArtifactRegistryError> {
        self.desktop_read_provenance
            .as_ref()
            .map_or(Ok(false), |proof| {
                proof
                    .matches_current_row(row)
                    .map_err(|_| corrupt("desktop_read_current"))
            })
    }

    /// Reobserve the exact immutable tuple through this repository's own pool.
    pub async fn validate_current(&self) -> Result<(), ArtifactRegistryError> {
        verify_artifact_registry_schema(&self.pool).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        let actual = decode_binding(
            client
                .query_opt(
                    READ_NAMESPACE,
                    &[&self.binding.deployment_id, &self.binding.tenant_id],
                )
                .await
                .map_err(|_| ArtifactRegistryError::Unavailable)?
                .ok_or_else(|| corrupt("dataset_binding"))?,
        )?;
        if actual.deployment_id != self.binding.deployment_id
            || actual.tenant_id != self.binding.tenant_id
            || actual.dataset_id != self.binding.dataset_id
            || actual.binding_schema != self.binding.binding_schema
            || actual.initial_origin != self.binding.initial_origin
            || actual.created_at != self.binding.created_at
        {
            return Err(corrupt("dataset_binding"));
        }
        Ok(())
    }

    #[cfg(feature = "server-runtime")]
    pub(crate) const fn pool(&self) -> &Pool {
        &self.pool
    }

    #[cfg(feature = "server-runtime")]
    pub(crate) fn owner(&self) -> Arc<()> {
        Arc::clone(&self.binding._owner)
    }

    /// Reobserve only storage lineage on the model factory's original transaction.
    /// This private bridge neither accepts another pool nor grants artifact/user authority.
    #[cfg(feature = "server-runtime")]
    pub(crate) async fn verify_model_dataset_in_transaction(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
    ) -> Result<(), ArtifactRegistryError> {
        fn infra(error: crate::db::InfraError) -> ArtifactRegistryError {
            match error {
                crate::db::InfraError::Connect { .. }
                | crate::db::InfraError::Query { .. }
                | crate::db::InfraError::RepositoryInvariant {
                    code: "custom_model_v2_schema_observation_unavailable",
                } => ArtifactRegistryError::Unavailable,
                _ => corrupt("model_dataset_schema"),
            }
        }
        if self.pool.is_closed() {
            return Err(corrupt("model_dataset_pool"));
        }
        native::validate_custom_model_v2_in_transaction(tx)
            .await
            .map_err(infra)?;
        let public: schema_facts::SchemaFacts = serde_json::from_str(REGISTERED_PUBLIC_SCHEMA)
            .map_err(|_| corrupt("public_schema_oracle"))?;
        let payload: String = tx
            .query_one(schema_facts::SCHEMA_FACTS_SQL, &[])
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
            .try_get(0)
            .map_err(|_| corrupt("public_schema"))?;
        let actual: schema_facts::SchemaFacts =
            serde_json::from_str(&payload).map_err(|_| corrupt("public_schema"))?;
        if actual != public {
            return Err(corrupt("public_schema"));
        }
        let expected: ArtifactRegistrySchemaFacts =
            serde_json::from_str(REGISTERED_INTERNAL_SCHEMA)
                .map_err(|_| corrupt("internal_schema_oracle"))?;
        if capture_schema_on_generic(tx).await? != expected {
            return Err(corrupt("internal_schema"));
        }
        crate::db::desktop_vault_canary::verify_model_dataset_shape_in_transaction(tx)
            .await
            .map_err(infra)?;

        // This is the shared final lineage stage, after consumer user/target/model locks.
        // Keep the actual immutable tuple and the canary absence/current row stable through ACK.
        let actual = decode_binding(
            tx.query_opt(
                &format!("{READ_NAMESPACE} FOR SHARE"),
                &[&self.binding.deployment_id, &self.binding.tenant_id],
            )
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?
            .ok_or_else(|| corrupt("dataset_binding"))?,
        )?;
        if actual.deployment_id != self.binding.deployment_id
            || actual.tenant_id != self.binding.tenant_id
            || actual.dataset_id != self.binding.dataset_id
            || actual.binding_schema != self.binding.binding_schema
            || actual.initial_origin != self.binding.initial_origin
            || actual.created_at != self.binding.created_at
        {
            return Err(corrupt("dataset_binding"));
        }
        tx.batch_execute("LOCK TABLE openbot_internal.desktop_vault_canaries IN SHARE MODE")
            .await
            .map_err(|_| ArtifactRegistryError::Unavailable)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(proof) = &self.desktop_read_provenance {
            let row = tx.query_one(
                "SELECT pcs.system_identifier::text AS read_database_system_identifier, d.oid AS read_database_oid, \
                 CASE WHEN octet_length(c.dataset_id)=32 THEN c.dataset_id END AS read_canary_dataset, \
                 CASE WHEN octet_length(c.deployment_id) BETWEEN 1 AND 512 THEN c.deployment_id END AS read_canary_deployment, \
                 CASE WHEN octet_length(c.tenant_id) BETWEEN 1 AND 512 THEN c.tenant_id END AS read_canary_tenant, \
                 CASE WHEN octet_length(c.key_id)=32 THEN c.key_id END AS read_canary_key, \
                 c.key_version AS read_canary_key_version, c.canary_schema AS read_canary_schema, \
                 CASE WHEN octet_length(c.encrypted_canary) BETWEEN 1 AND 4096 THEN c.encrypted_canary END AS read_canary_encrypted \
                 FROM (SELECT 1) anchor LEFT JOIN pg_control_system() pcs ON true \
                 LEFT JOIN pg_database d ON d.datname=current_database() \
                 LEFT JOIN openbot_internal.desktop_vault_canaries c \
                 ON c.deployment_id=$1 AND c.tenant_id=$2 AND c.key_version=1",
                &[&self.binding.deployment_id, &self.binding.tenant_id],
            ).await.map_err(|_| ArtifactRegistryError::Unavailable)?;
            if !proof
                .matches_current_row(&row)
                .map_err(|_| corrupt("model_dataset_canary"))?
            {
                return Err(corrupt("model_dataset_canary"));
            }
            return Ok(());
        }
        let has_canary: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM openbot_internal.desktop_vault_canaries WHERE deployment_id=$1 AND tenant_id=$2)",
            &[&self.binding.deployment_id, &self.binding.tenant_id],
        ).await.map_err(|_| ArtifactRegistryError::Unavailable)?
            .try_get(0).map_err(|_| corrupt("model_dataset_canary"))?;
        if has_canary {
            return Err(ArtifactRegistryError::ProofRequired);
        }
        Ok(())
    }
}

/// Extract actual internal facts independently, including disabled hooks and guard body changes.
pub async fn capture_artifact_registry_schema(
    pool: &Pool,
) -> Result<ArtifactRegistrySchemaFacts, ArtifactRegistryError> {
    let client = pool
        .get()
        .await
        .map_err(|_| ArtifactRegistryError::Unavailable)?;
    capture_schema_on(&client).await
}

/// Verify the registered native/public layout and the independent exact internal oracle.
pub async fn verify_artifact_registry_schema(pool: &Pool) -> Result<(), ArtifactRegistryError> {
    let client = pool
        .get()
        .await
        .map_err(|_| ArtifactRegistryError::Unavailable)?;
    verify_artifact_registry_schema_on(&client).await
}

/// Verify the same native/public/internal facts on the caller's original immutable client.
pub(crate) async fn verify_artifact_registry_schema_on(
    client: &tokio_postgres::Client,
) -> Result<(), ArtifactRegistryError> {
    native::validate_current(client)
        .await
        .map_err(|error| match error {
            crate::db::InfraError::Connect { .. } | crate::db::InfraError::Query { .. } => {
                ArtifactRegistryError::Unavailable
            }
            _ => corrupt("native_schema"),
        })?;
    let public: schema_facts::SchemaFacts = serde_json::from_str(REGISTERED_PUBLIC_SCHEMA)
        .map_err(|_| corrupt("public_schema_oracle"))?;
    if schema_facts::fetch(client)
        .await
        .map_err(|_| ArtifactRegistryError::Unavailable)?
        != public
    {
        return Err(corrupt("public_schema"));
    }
    let expected: ArtifactRegistrySchemaFacts = serde_json::from_str(REGISTERED_INTERNAL_SCHEMA)
        .map_err(|_| corrupt("internal_schema_oracle"))?;
    if capture_schema_on(client).await? != expected {
        return Err(corrupt("internal_schema"));
    }
    Ok(())
}

async fn capture_schema_on(
    client: &tokio_postgres::Client,
) -> Result<ArtifactRegistrySchemaFacts, ArtifactRegistryError> {
    capture_schema_on_generic(client).await
}

async fn capture_schema_on_generic<C: tokio_postgres::GenericClient + Sync>(
    client: &C,
) -> Result<ArtifactRegistrySchemaFacts, ArtifactRegistryError> {
    let payload: String = client
        .query_one(ARTIFACT_REGISTRY_SCHEMA_SQL, &[])
        .await
        .map_err(|_| ArtifactRegistryError::Unavailable)?
        .try_get(0)
        .map_err(|_| corrupt("internal_schema"))?;
    serde_json::from_str(&payload).map_err(|_| corrupt("internal_schema"))
}

fn decode_binding(row: Row) -> Result<VerifiedArtifactDatasetBinding, ArtifactRegistryError> {
    let deployment_id: String = row
        .try_get("deployment_id")
        .map_err(|_| corrupt("deployment_id"))?;
    let tenant_id: String = row.try_get("tenant_id").map_err(|_| corrupt("tenant_id"))?;
    let dataset_id: String = row
        .try_get("dataset_id")
        .map_err(|_| corrupt("dataset_id"))?;
    let binding_schema: i16 = row
        .try_get("binding_schema")
        .map_err(|_| corrupt("binding_schema"))?;
    let initial_origin: String = row
        .try_get("initial_origin")
        .map_err(|_| corrupt("initial_origin"))?;
    let created_at = row
        .try_get("created_at")
        .map_err(|_| corrupt("created_at"))?;
    if !is_valid_artifact_identity(&deployment_id)
        || !is_valid_artifact_identity(&tenant_id)
        || !is_valid_artifact_identity(&dataset_id)
        || binding_schema != 1
        || !matches!(
            initial_origin.as_str(),
            "desktop_canary" | "server_first_adoption"
        )
    {
        return Err(corrupt("dataset_binding"));
    }
    Ok(VerifiedArtifactDatasetBinding {
        deployment_id,
        tenant_id,
        dataset_id,
        binding_schema,
        initial_origin,
        created_at,
        _owner: Arc::new(()),
    })
}

fn validate_namespace(deployment: &str, tenant: &str) -> Result<(), ArtifactRegistryError> {
    for (field, value) in [("deployment_id", deployment), ("tenant_id", tenant)] {
        if !is_valid_artifact_identity(value) {
            return Err(ArtifactRegistryError::InvalidInput { field });
        }
    }
    Ok(())
}

fn mint_dataset() -> Result<String, ArtifactRegistryError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ArtifactRegistryError::Unavailable)?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Ok(output)
}

const fn corrupt(field: &'static str) -> ArtifactRegistryError {
    ArtifactRegistryError::Corrupt { field }
}
