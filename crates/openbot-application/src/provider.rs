//! Provider-neutral streaming port；vendor DTO 不穿过此模块（v3 §7.3）。

mod content;

use async_trait::async_trait;
use core::time::Duration;
use openbot_contracts::auth::AuthContext;
use openbot_contracts::remote_interrupt::is_remote_interrupt_request_id;
use openbot_domain::vault::SecretBytes;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;
use time::OffsetDateTime;
use url::Url;

use crate::RunExecutionLease;

/// Loading a fresh authoritative actor context for an asynchronous Agent effect failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentAuthorizationError {
    /// Database/ACL source unavailable.
    #[error("agent_authorization_unavailable")]
    Unavailable,
    /// Actor/run/lease no longer authorized. This remains non-enumerating.
    #[error("agent_authorization_refused")]
    Refused,
    /// Durable role/generation data is malformed.
    #[error("agent_authorization_corrupt field={field}")]
    Corrupt {
        /// Static field name only.
        field: &'static str,
    },
}

/// Rebuilds AuthContext from current database ACL before every Agent tool effect.
#[async_trait]
pub trait AgentAuthorizationSource: Send + Sync {
    /// Load a fresh non-serializable context bound to the active run lease.
    async fn load(&self, lease: &RunExecutionLease)
    -> Result<AuthContext, AgentAuthorizationError>;
}

/// Authoritative remote AG-UI route loaded from the Bot row and active run lease.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteAguiRoute {
    endpoint: String,
    thread_id: String,
    local_run_id: String,
    protocol_run_id: String,
    parent_protocol_run_id: Option<String>,
    resume: Option<Box<ProviderRemoteResume>>,
    bot_id: String,
    run_assertion: Option<String>,
    authorization: Option<RemoteAguiAuthorization>,
}

impl RemoteAguiRoute {
    /// Construct from trusted PostgreSQL/configuration data.
    pub fn new(
        endpoint: String,
        thread_id: String,
        run_id: String,
        bot_id: String,
        run_assertion: Option<String>,
    ) -> Result<Self, AgentContextError> {
        if [&endpoint, &thread_id, &run_id, &bot_id]
            .into_iter()
            .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || run_assertion
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.as_bytes().contains(&0))
        {
            return Err(AgentContextError::Corrupt {
                field: "remote_agui_route",
            });
        }
        Ok(Self {
            endpoint,
            thread_id,
            local_run_id: run_id.clone(),
            protocol_run_id: run_id,
            parent_protocol_run_id: None,
            resume: None,
            bot_id,
            run_assertion,
            authorization: None,
        })
    }

    /// Attach a Vault-opened Authorization value. The route shares the one zeroizing allocation.
    #[must_use]
    pub fn with_authorization(mut self, authorization: RemoteAguiAuthorization) -> Self {
        self.authorization = Some(authorization);
        self
    }

    /// Endpoint. Debug never renders it.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Authoritative thread id.
    #[must_use]
    pub fn thread_id(&self) -> &str {
        &self.thread_id
    }

    /// Authoritative run id.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.protocol_run_id
    }

    /// Authoritative local durable run id; unlike protocol run id, it never changes on resume.
    #[must_use]
    pub fn local_run_id(&self) -> &str {
        &self.local_run_id
    }

    /// Previous AG-UI protocol run id when this request resumes an interrupt.
    #[must_use]
    pub fn parent_protocol_run_id(&self) -> Option<&str> {
        self.parent_protocol_run_id.as_deref()
    }

    /// Bounded resume entries for the next AG-UI request.
    #[must_use]
    pub fn resume(&self) -> Option<&ProviderRemoteResume> {
        self.resume.as_deref()
    }

    /// Advance only the remote protocol invocation while retaining local run authority.
    ///
    /// # Errors
    ///
    /// Rejects a resume whose parent does not equal the current protocol run id.
    pub fn with_resume(mut self, resume: ProviderRemoteResume) -> Result<Self, AgentContextError> {
        if resume.parent_protocol_run_id() != self.protocol_run_id {
            return Err(AgentContextError::Corrupt {
                field: "remote_resume_parent",
            });
        }
        let parent_protocol_run_id = std::mem::replace(
            &mut self.protocol_run_id,
            resume.protocol_run_id().to_owned(),
        );
        self.parent_protocol_run_id = Some(parent_protocol_run_id);
        self.resume = Some(Box::new(resume));
        Ok(self)
    }

    /// Attach a resume to a freshly reloaded route while preserving a prior protocol cursor.
    ///
    /// A context reload intentionally refreshes endpoint, assertion, authorization and tool
    /// grants, so it starts with `protocol_run_id == local_run_id`. The runtime supplies the
    /// cursor that it observed from the preceding typed provider session; both that cursor and
    /// the resume parent must match before the fresh authority can be used for another request.
    pub fn with_fresh_resume(
        mut self,
        current_protocol_run_id: &str,
        resume: ProviderRemoteResume,
    ) -> Result<Self, AgentContextError> {
        if self.protocol_run_id != self.local_run_id
            || self.parent_protocol_run_id.is_some()
            || self.resume.is_some()
            || current_protocol_run_id.is_empty()
            || current_protocol_run_id.as_bytes().contains(&0)
            || resume.parent_protocol_run_id() != current_protocol_run_id
        {
            return Err(AgentContextError::Corrupt {
                field: "remote_resume_parent",
            });
        }
        self.parent_protocol_run_id = Some(current_protocol_run_id.to_owned());
        self.protocol_run_id = resume.protocol_run_id().to_owned();
        self.resume = Some(Box::new(resume));
        Ok(self)
    }

    /// Authoritative Bot id.
    #[must_use]
    pub fn bot_id(&self) -> &str {
        &self.bot_id
    }

    /// Optional short-lived assertion. Absence means no deployment tool may be offered.
    #[must_use]
    pub fn run_assertion(&self) -> Option<&str> {
        self.run_assertion.as_deref()
    }

    /// Optional write-only customer Agent Authorization value.
    #[must_use]
    pub const fn authorization(&self) -> Option<&RemoteAguiAuthorization> {
        self.authorization.as_ref()
    }
}

impl core::fmt::Debug for RemoteAguiRoute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteAguiRoute")
            .field("endpoint", &"<redacted-origin>")
            .field("thread_id", &self.thread_id)
            .field("local_run_id", &self.local_run_id)
            .field("protocol_run_id", &self.protocol_run_id)
            .field("parent_protocol_run_id", &self.parent_protocol_run_id)
            .field(
                "resume",
                &self.resume.as_ref().map(|value| value.entries().len()),
            )
            .field("bot_id", &self.bot_id)
            .field("has_run_assertion", &self.run_assertion.is_some())
            .field("has_authorization", &self.authorization.is_some())
            .finish()
    }
}

/// Vault-opened remote Agent Authorization value. It is never serde/displayable.
#[derive(Clone)]
pub struct RemoteAguiAuthorization(Arc<SecretBytes>);

impl RemoteAguiAuthorization {
    /// Take ownership of one already validated non-empty header value.
    pub fn new(value: SecretBytes) -> Result<Self, AgentContextError> {
        if value.is_empty()
            || value.len() > 16 * 1_024
            || value.expose().contains(&0)
            || core::str::from_utf8(value.expose()).is_err()
        {
            return Err(AgentContextError::Corrupt {
                field: "remote_authorization",
            });
        }
        Ok(Self(Arc::new(value)))
    }

    /// Explicitly expose UTF-8 only at the SafeDialer request boundary.
    pub fn expose(&self) -> Result<&str, AgentContextError> {
        core::str::from_utf8(self.0.expose()).map_err(|_| AgentContextError::Corrupt {
            field: "remote_authorization",
        })
    }
}

impl core::fmt::Debug for RemoteAguiAuthorization {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl PartialEq for RemoteAguiAuthorization {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for RemoteAguiAuthorization {}

/// Provider routing loaded from authoritative Bot configuration or an explicit run snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderRoute {
    /// Package `model.yaml` 固定 OpenAI。
    PackageOpenAi,
    /// Managed slot 读取 deployment `BOT_PROVIDER/BOT_MODEL` config。
    Managed,
    /// Customer-owned remote AG-UI endpoint.
    RemoteAgUi(RemoteAguiRoute),
    /// Personal connection frozen to this run, revalidated before every actual start.
    CustomModel(RunModelBinding),
}

/// 当前 dataset 最初登记来源的纯值；不证明本次读取或恢复授权。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunModelDatasetInitialOrigin {
    /// 原 Desktop canary 登记。
    DesktopCanary,
    /// 原 Server 首次接纳登记。
    ServerFirstAdoption,
}

impl RunModelDatasetInitialOrigin {
    /// 返回唯一持久化拼写。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DesktopCanary => "desktop_canary",
            Self::ServerFirstAdoption => "server_first_adoption",
        }
    }
}

impl core::fmt::Debug for RunModelDatasetInitialOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelDatasetInitialOrigin([redacted])")
    }
}

/// v2 的冻结凭据策略纯值，不开放动态刷新。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunModelCredentialPolicy {
    /// 使用接受时冻结的原 custom secret revision。
    CustomFixedSecretRevisionV1,
}

impl RunModelCredentialPolicy {
    /// 返回唯一持久化拼写。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustomFixedSecretRevisionV1 => "custom_fixed_secret_revision_v1",
        }
    }
}

impl core::fmt::Debug for RunModelCredentialPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelCredentialPolicy([redacted])")
    }
}

/// 同原 dataset 的不可变纯值快照；构造不授予 current grant。
#[derive(Clone, PartialEq, Eq)]
pub struct RunModelDatasetSnapshot {
    dataset_id: String,
    binding_schema: i16,
    initial_origin: RunModelDatasetInitialOrigin,
    created_at: time::OffsetDateTime,
}

impl RunModelDatasetSnapshot {
    /// 只核 dataset 有限值与 schema，原事务负责证明其来源。
    pub fn new(
        dataset_id: String,
        binding_schema: i16,
        initial_origin: RunModelDatasetInitialOrigin,
        created_at: time::OffsetDateTime,
    ) -> Result<Self, AgentContextError> {
        if dataset_id.is_empty()
            || dataset_id.len() > 512
            || dataset_id
                .chars()
                .any(|c| matches!(u32::from(c), 0..=0x1f | 0x7f..=0x9f))
            || binding_schema != 1
        {
            return Err(AgentContextError::Corrupt {
                field: "run_model_dataset",
            });
        }
        Ok(Self {
            dataset_id,
            binding_schema,
            initial_origin,
            created_at,
        })
    }

    /// 原 dataset 标识，未作归一化。
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }
    /// 固定绑定 schema。
    pub fn binding_schema(&self) -> i16 {
        self.binding_schema
    }
    /// 原首次登记来源；不是可重建的 grant。
    pub fn initial_origin(&self) -> RunModelDatasetInitialOrigin {
        self.initial_origin
    }
    /// 原登记时间，不是本次读取时间。
    pub fn created_at(&self) -> time::OffsetDateTime {
        self.created_at
    }
}

impl core::fmt::Debug for RunModelDatasetSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelDatasetSnapshot([redacted])")
    }
}

/// 完整原 v2 选择、dataset 和冻结 policy；保留 UUID 大小写。
#[derive(Clone, PartialEq, Eq)]
pub struct RunModelV2Snapshot {
    selection: openbot_contracts::versioned_model_selection::RunModelSelectionV2,
    dataset: RunModelDatasetSnapshot,
    credential_policy: RunModelCredentialPolicy,
}

impl RunModelV2Snapshot {
    /// 有限值校验；该桥不访问数据库、Vault 或网络。
    pub fn new(
        selection: openbot_contracts::versioned_model_selection::RunModelSelectionV2,
        dataset: RunModelDatasetSnapshot,
        credential_policy: RunModelCredentialPolicy,
    ) -> Result<Self, AgentContextError> {
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, VersionedRunModelSelection,
        };
        if !VersionedRunModelSelection::V2(selection.clone()).is_valid()
            || selection.source() != ModelSelectionIntentSource::Custom
        {
            return Err(AgentContextError::Corrupt {
                field: "run_model_v2_snapshot",
            });
        }
        Ok(Self {
            selection,
            dataset,
            credential_policy,
        })
    }
    /// 借用完整原选择意图。
    pub fn selection(&self) -> &openbot_contracts::versioned_model_selection::RunModelSelectionV2 {
        &self.selection
    }
    /// 借用完整原 dataset tuple。
    pub fn dataset(&self) -> &RunModelDatasetSnapshot {
        &self.dataset
    }
    /// 返回固定凭据策略。
    pub fn credential_policy(&self) -> RunModelCredentialPolicy {
        self.credential_policy
    }
}

impl core::fmt::Debug for RunModelV2Snapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelV2Snapshot([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq)]
enum RunModelBindingDetails {
    V1,
    V2(Box<RunModelV2Snapshot>),
}

#[cfg(test)]
mod custom_model_v2_value_tests {
    use super::*;

    #[test]
    fn dataset_snapshot_enforces_utf8_bytes_c0_c1_and_schema_without_trimming() {
        let origin = RunModelDatasetInitialOrigin::ServerFirstAdoption;
        let time = time::OffsetDateTime::UNIX_EPOCH;
        for valid in ["é".repeat(256), " historical dataset ".to_owned()] {
            let value = RunModelDatasetSnapshot::new(valid.clone(), 1, origin, time).unwrap();
            assert_eq!(value.dataset_id(), valid);
            assert_eq!(value.created_at(), time);
            assert_eq!(value.initial_origin().as_str(), "server_first_adoption");
        }
        for invalid in [
            String::new(),
            "é".repeat(257),
            format!("dataset{}", char::from_u32(0x1f).unwrap()),
            format!("dataset{}", char::from_u32(0x7f).unwrap()),
            format!("dataset{}", char::from_u32(0x9f).unwrap()),
        ] {
            assert!(RunModelDatasetSnapshot::new(invalid, 1, origin, time).is_err());
        }
        assert!(RunModelDatasetSnapshot::new("dataset".to_owned(), 2, origin, time).is_err());
        let original = RunModelDatasetSnapshot::new("dataset".to_owned(), 1, origin, time).unwrap();
        assert!(!format!("{original:?}").contains("dataset"));
    }

    #[test]
    fn v2_pure_snapshot_rejects_unsupported_source_and_retains_complete_values() {
        use openbot_contracts::versioned_model_selection::{
            ModelSelectionIntentSource, RunModelSelectionV2,
        };
        let dataset = RunModelDatasetSnapshot::new(
            "original-dataset".to_owned(),
            1,
            RunModelDatasetInitialOrigin::DesktopCanary,
            time::OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        let selection = |source| {
            RunModelSelectionV2::new(
                source,
                "ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456".to_owned(),
                7,
                "custom:abcdef12-abcd-4bcd-8abc-abcdef123456".to_owned(),
                9,
            )
            .unwrap()
        };
        for source in [
            ModelSelectionIntentSource::SdkGateway,
            ModelSelectionIntentSource::AccountBridge,
        ] {
            assert!(
                RunModelV2Snapshot::new(
                    selection(source),
                    dataset.clone(),
                    RunModelCredentialPolicy::CustomFixedSecretRevisionV1
                )
                .is_err()
            );
        }
        let value = RunModelV2Snapshot::new(
            selection(ModelSelectionIntentSource::Custom),
            dataset.clone(),
            RunModelCredentialPolicy::CustomFixedSecretRevisionV1,
        )
        .unwrap();
        assert_eq!(
            value.selection().connection_id(),
            "ABCDEF12-ABCD-4BCD-8ABC-ABCDEF123456"
        );
        assert_eq!(value.selection().expected_catalog_revision(), 9);
        assert_eq!(value.dataset(), &dataset);
        assert_eq!(
            value.credential_policy().as_str(),
            "custom_fixed_secret_revision_v1"
        );
        assert!(!format!("{value:?}").contains("original-dataset"));
    }
}

/// Immutable Rust-only routing evidence. This is not a credential or an authorization substitute.
/// Infra must validate current database authority again before opening any provider request.
#[derive(Clone, PartialEq, Eq)]
pub struct RunModelBinding {
    deployment: openbot_contracts::ids::DeploymentId,
    tenant: openbot_contracts::ids::TenantId,
    run_id: openbot_contracts::ids::RunId,
    thread_id: openbot_contracts::ids::ThreadId,
    bot_id: openbot_contracts::ids::BotId,
    actor: openbot_contracts::ids::ActorId,
    fencing: openbot_domain::thread::FencingToken,
    auth_generation: openbot_contracts::auth::AuthGeneration,
    connection_id: String,
    connection_revision: i64,
    secret_id: String,
    protocol: openbot_contracts::model_connections::CustomModelProtocol,
    endpoint: String,
    model: String,
    details: RunModelBindingDetails,
}

impl RunModelBinding {
    /// Construct only from a verified PostgreSQL run snapshot and current configuration.
    /// This checked constructor is public solely for Rust crate boundaries; no Serde input exists.
    /// A caller cannot use construction itself as proof of current role, generation or ownership.
    pub fn from_verified_snapshot(
        lease: &RunExecutionLease,
        deployment: openbot_contracts::ids::DeploymentId,
        tenant: openbot_contracts::ids::TenantId,
        auth_generation: openbot_contracts::auth::AuthGeneration,
        selection: openbot_contracts::model_connections::RunModelSelection,
        secret_id: String,
        configuration: crate::model_connections::NormalizedModelConnection,
    ) -> Result<Self, AgentContextError> {
        let invalid = || AgentContextError::Corrupt {
            field: "run_model_binding",
        };
        let secret_shape = openbot_contracts::model_connections::RunModelSelection {
            connection_id: secret_id.clone(),
            expected_revision: 1,
        };
        if !selection.is_valid()
            || !secret_shape.is_valid()
            || i64::try_from(auth_generation.get()).is_err()
            || [
                deployment.as_str(),
                tenant.as_str(),
                lease.run_id().as_str(),
                lease.thread_id().as_str(),
                lease.bot_id().as_str(),
                lease.actor_id().as_str(),
            ]
            .into_iter()
            .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || !configuration.enabled
        {
            return Err(invalid());
        }
        let normalized = crate::model_connections::normalize_model_configuration(
            &configuration.name,
            configuration.protocol,
            &configuration.endpoint,
            &configuration.model,
            true,
        )
        .map_err(|_| invalid())?;
        if normalized != configuration {
            return Err(invalid());
        }
        Ok(Self {
            deployment,
            tenant,
            run_id: lease.run_id().clone(),
            thread_id: lease.thread_id().clone(),
            bot_id: lease.bot_id().clone(),
            actor: lease.actor_id().clone(),
            fencing: lease.fencing(),
            auth_generation,
            connection_id: selection.connection_id.to_ascii_lowercase(),
            connection_revision: selection.expected_revision,
            secret_id: secret_id.to_ascii_lowercase(),
            protocol: configuration.protocol,
            endpoint: configuration.endpoint,
            model: configuration.model,
            details: RunModelBindingDetails::V1,
        })
    }

    /// 从原事务已核事实桥接完整 v2；构造本身不是当前权限证明。
    pub fn from_verified_v2_snapshot(
        lease: &RunExecutionLease,
        deployment: openbot_contracts::ids::DeploymentId,
        tenant: openbot_contracts::ids::TenantId,
        auth_generation: openbot_contracts::auth::AuthGeneration,
        snapshot: RunModelV2Snapshot,
        secret_id: String,
        configuration: crate::model_connections::NormalizedModelConnection,
    ) -> Result<Self, AgentContextError> {
        let common_selection = openbot_contracts::model_connections::RunModelSelection {
            connection_id: snapshot.selection().connection_id().to_owned(),
            expected_revision: snapshot.selection().expected_connection_revision(),
        };
        let mut binding = Self::from_verified_snapshot(
            lease,
            deployment,
            tenant,
            auth_generation,
            common_selection,
            secret_id,
            configuration,
        )?;
        binding.details = RunModelBindingDetails::V2(Box::new(snapshot));
        Ok(binding)
    }

    /// Some 只表示此纯值是完整 v2；None 精确表示原 v1 binding。
    pub fn v2_snapshot(&self) -> Option<&RunModelV2Snapshot> {
        match &self.details {
            RunModelBindingDetails::V1 => None,
            RunModelBindingDetails::V2(snapshot) => Some(snapshot.as_ref()),
        }
    }

    /// Compare immutable run identity only; journal sequence advances across sampling rounds.
    pub fn matches_lease(&self, lease: &RunExecutionLease) -> bool {
        self.run_id == *lease.run_id()
            && self.thread_id == *lease.thread_id()
            && self.bot_id == *lease.bot_id()
            && self.actor == *lease.actor_id()
            && self.fencing == lease.fencing()
    }
    /// Reconstruct the identity used for a fresh read; sequence zero is never a write capability.
    pub fn identity_lease(&self) -> Result<RunExecutionLease, AgentContextError> {
        RunExecutionLease::new(
            self.run_id.clone(),
            self.thread_id.clone(),
            self.bot_id.clone(),
            self.actor.clone(),
            self.fencing,
            0,
        )
        .map_err(|_| AgentContextError::Corrupt {
            field: "run_model_binding",
        })
    }
    /// Fixed deployment identity.
    pub fn deployment(&self) -> &openbot_contracts::ids::DeploymentId {
        &self.deployment
    }
    /// Fixed tenant identity.
    pub fn tenant(&self) -> &openbot_contracts::ids::TenantId {
        &self.tenant
    }
    /// Current-authority comparison generation frozen when Begin committed.
    pub const fn auth_generation(&self) -> openbot_contracts::auth::AuthGeneration {
        self.auth_generation
    }
    /// Owning principal, never selected by the renderer.
    pub fn actor(&self) -> &openbot_contracts::ids::ActorId {
        &self.actor
    }
    /// Private connection reference.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
    /// Frozen connection revision.
    pub const fn connection_revision(&self) -> i64 {
        self.connection_revision
    }
    /// Private credential reference, not secret material or an authorization grant.
    pub fn secret_id(&self) -> &str {
        &self.secret_id
    }
    /// Frozen closed wire protocol.
    pub const fn protocol(&self) -> openbot_contracts::model_connections::CustomModelProtocol {
        self.protocol
    }
    /// Canonical final provider URL for this run; never expose through public events.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    /// Frozen model identifier for the provider body.
    pub fn model(&self) -> &str {
        &self.model
    }
}

impl core::fmt::Debug for RunModelBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunModelBinding([redacted])")
    }
}

/// Provider family bound into an operator-attested price snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderBillingFamily {
    /// OpenAI or an explicitly compatible endpoint.
    OpenAiCompatible,
    /// Anthropic Messages.
    Anthropic,
    /// Google Generative AI.
    Google,
}

impl ProviderBillingFamily {
    /// Stable PostgreSQL/audit literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "openai_compatible",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
        }
    }

    /// Parse the stable storage literal.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "openai_compatible" => Some(Self::OpenAiCompatible),
            "anthropic" => Some(Self::Anthropic),
            "google" => Some(Self::Google),
            _ => None,
        }
    }
}

/// Invalid operator-attested rate-card field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderRateCardError {
    /// Provider/model identity is not bounded or canonical.
    #[error("provider_rate_card_identity_invalid")]
    Identity,
    /// Currency must be an explicit three-letter uppercase code.
    #[error("provider_rate_card_currency_invalid")]
    Currency,
    /// Source must be a credential-free HTTPS URL with no query or fragment.
    #[error("provider_rate_card_source_invalid")]
    Source,
    /// Source digest must be lowercase SHA-256.
    #[error("provider_rate_card_digest_invalid")]
    Digest,
    /// Observation time must be at or after the Unix epoch.
    #[error("provider_rate_card_observed_at_invalid")]
    ObservedAt,
    /// A rate cannot fit the PostgreSQL signed-bigint boundary.
    #[error("provider_rate_card_rate_invalid")]
    Rate,
}

/// Operator-attested immutable maximum-rate provenance for one provider/model pair.
///
/// OpenBot does not ship mutable vendor list prices. The deployment owner records the rate that
/// bounds its contract together with the source document hash and observation time. Maximum rates
/// make the counter conservative when a vendor reports no stable cache-discount breakdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRateCard {
    family: ProviderBillingFamily,
    model: String,
    currency: String,
    max_input_micro_units_per_million_tokens: u64,
    max_output_micro_units_per_million_tokens: u64,
    source_url: String,
    source_sha256: String,
    observed_at: OffsetDateTime,
}

/// Explicit input for one operator-attested maximum-rate snapshot.
pub struct ProviderRateCardInput {
    /// Provider family.
    pub family: ProviderBillingFamily,
    /// Exact provider model id.
    pub model: String,
    /// Three-letter uppercase currency code; OpenBot performs no conversion.
    pub currency: String,
    /// Maximum micro currency units per one million input tokens.
    pub max_input_micro_units_per_million_tokens: u64,
    /// Maximum micro currency units per one million output tokens.
    pub max_output_micro_units_per_million_tokens: u64,
    /// Credential-free HTTPS source URL.
    pub source_url: String,
    /// Lowercase SHA-256 of the source document.
    pub source_sha256: String,
    /// Operator observation time.
    pub observed_at: OffsetDateTime,
}

impl ProviderRateCard {
    /// Validate and canonicalize one explicit maximum-rate snapshot.
    pub fn new(input: ProviderRateCardInput) -> Result<Self, ProviderRateCardError> {
        let ProviderRateCardInput {
            family,
            model,
            currency,
            max_input_micro_units_per_million_tokens,
            max_output_micro_units_per_million_tokens,
            source_url,
            source_sha256,
            observed_at,
        } = input;
        if model.is_empty() || model.len() > 256 || model.as_bytes().contains(&0) {
            return Err(ProviderRateCardError::Identity);
        }
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(ProviderRateCardError::Currency);
        }
        if max_input_micro_units_per_million_tokens > i64::MAX as u64
            || max_output_micro_units_per_million_tokens > i64::MAX as u64
        {
            return Err(ProviderRateCardError::Rate);
        }
        let source = Url::parse(&source_url).map_err(|_| ProviderRateCardError::Source)?;
        if source.scheme() != "https"
            || source.host_str().is_none()
            || !source.username().is_empty()
            || source.password().is_some()
            || source.query().is_some()
            || source.fragment().is_some()
            || source.as_str().len() > 2048
        {
            return Err(ProviderRateCardError::Source);
        }
        if source_sha256.len() != 64
            || !source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProviderRateCardError::Digest);
        }
        if observed_at < OffsetDateTime::UNIX_EPOCH {
            return Err(ProviderRateCardError::ObservedAt);
        }
        Ok(Self {
            family,
            model,
            currency,
            max_input_micro_units_per_million_tokens,
            max_output_micro_units_per_million_tokens,
            source_url: source.to_string(),
            source_sha256,
            observed_at,
        })
    }

    /// Provider family.
    #[must_use]
    pub const fn family(&self) -> ProviderBillingFamily {
        self.family
    }

    /// Exact configured model.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Currency code. No conversion is performed.
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Maximum micro currency units charged per one million input tokens.
    #[must_use]
    pub const fn max_input_rate(&self) -> u64 {
        self.max_input_micro_units_per_million_tokens
    }

    /// Maximum micro currency units charged per one million output tokens.
    #[must_use]
    pub const fn max_output_rate(&self) -> u64 {
        self.max_output_micro_units_per_million_tokens
    }

    /// Canonical credential-free HTTPS provenance URL.
    #[must_use]
    pub fn source_url(&self) -> &str {
        &self.source_url
    }

    /// Lowercase source-document SHA-256.
    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// When the operator observed the attested rate.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }
}

/// Exact arithmetic upper bound under operator-attested maximum rates in one currency.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderCostUpperBound {
    micro_units: u64,
    remainder_millionths: u32,
}

impl ProviderCostUpperBound {
    /// Restore a durable counter.
    pub fn from_parts(
        micro_units: u64,
        remainder_millionths: u32,
    ) -> Result<Self, ProviderRateCardError> {
        if remainder_millionths >= 1_000_000 || micro_units > i64::MAX as u64 {
            return Err(ProviderRateCardError::Rate);
        }
        Ok(Self {
            micro_units,
            remainder_millionths,
        })
    }

    /// Add one normalized usage without floating point or per-sampling rounding.
    pub fn accrue(
        self,
        usage: ProviderUsage,
        rate: &ProviderRateCard,
    ) -> Result<Self, ProviderRateCardError> {
        let input = u128::from(usage.input_tokens)
            .checked_mul(u128::from(rate.max_input_rate()))
            .ok_or(ProviderRateCardError::Rate)?;
        let output = u128::from(usage.output_tokens)
            .checked_mul(u128::from(rate.max_output_rate()))
            .ok_or(ProviderRateCardError::Rate)?;
        let numerator = input
            .checked_add(output)
            .and_then(|value| value.checked_add(u128::from(self.remainder_millionths)))
            .ok_or(ProviderRateCardError::Rate)?;
        let whole =
            u64::try_from(numerator / 1_000_000).map_err(|_| ProviderRateCardError::Rate)?;
        let micro_units = self
            .micro_units
            .checked_add(whole)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(ProviderRateCardError::Rate)?;
        Ok(Self {
            micro_units,
            remainder_millionths: u32::try_from(numerator % 1_000_000)
                .map_err(|_| ProviderRateCardError::Rate)?,
        })
    }

    /// Whole micro currency units already carried from exact arithmetic.
    #[must_use]
    pub const fn micro_units(self) -> u64 {
        self.micro_units
    }

    /// Remaining millionths of one micro currency unit.
    #[must_use]
    pub const fn remainder_millionths(self) -> u32 {
        self.remainder_millionths
    }

    /// Conservative billable amount rounded up only at the aggregate boundary.
    #[must_use]
    pub fn billed_upper_bound_micro_units(self) -> Option<u64> {
        self.micro_units
            .checked_add(u64::from(self.remainder_millionths != 0))
    }
}

/// SafeDialer/SSE transport failure without remote body text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteAguiTransportError {
    /// URL, scheme, or destination policy rejected the request before any socket was opened.
    #[error("remote_agui_destination_rejected")]
    DestinationRejected,
    /// DNS/connect/TLS failed before the request became commit-unknown.
    #[error("remote_agui_unavailable")]
    Unavailable,
    /// Request may have reached the endpoint; replay is unsafe.
    #[error("remote_agui_commit_unknown")]
    CommitUnknown,
    /// Endpoint authentication rejected.
    #[error("remote_agui_authentication")]
    Authentication,
    /// Explicit 429.
    #[error("remote_agui_rate_limited")]
    RateLimited,
    /// Explicit retryable 5xx.
    #[error("remote_agui_server_unavailable")]
    ServerUnavailable,
    /// Status/content-type/SSE framing is invalid.
    #[error("remote_agui_invalid_response")]
    InvalidResponse,
    /// Real response-body read gap exceeded the watchdog.
    #[error("remote_agui_stream_stalled")]
    StreamStalled,
}

/// Complete SSE `data:` values from the unique safe transport.
#[async_trait]
pub trait RemoteAguiEventStream: Send {
    /// Read the next complete event payload.
    async fn next_data(&mut self) -> Result<Option<String>, RemoteAguiTransportError>;
}

/// Raw HTTP/SSE port. Semantic decoding remains in `openbot-agent`.
#[async_trait]
pub trait RemoteAguiTransport: Send + Sync {
    /// Resolve and apply current scheme/egress policy without sending a request. Runtime still
    /// repeats the same decision immediately before every connection and redirect.
    async fn validate_endpoint(&self, _endpoint: &str) -> Result<(), RemoteAguiTransportError> {
        Err(RemoteAguiTransportError::Unavailable)
    }

    /// POST one encoded RunAgentInput to a trusted endpoint.
    async fn start(
        &self,
        endpoint: &str,
        authorization: Option<&RemoteAguiAuthorization>,
        body: Vec<u8>,
    ) -> Result<Box<dyn RemoteAguiEventStream>, RemoteAguiTransportError>;
}

/// Provider input message role。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderMessageRole {
    /// Standing/system instruction。
    System,
    /// User。
    User,
    /// Assistant history。
    Assistant,
    /// Tool result history。
    Tool,
}

/// A normalized assistant tool call retained as part of the next sampling history.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderToolCall {
    /// Vendor call id used only to pair the subsequent tool result.
    pub call_id: String,
    /// Authoritative catalog name after application validation.
    pub name: String,
    /// Validated object arguments. Debug never renders them.
    pub arguments: Value,
}

impl core::fmt::Debug for ProviderToolCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderToolCall")
            .field("call_id", &self.call_id)
            .field("name", &self.name)
            .field("arguments", &"[redacted]")
            .finish()
    }
}

/// Provider-neutral input message；Debug 只显示长度。
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderMessage {
    /// Role。
    pub role: ProviderMessageRole,
    /// Plain text projection. It may be empty on an assistant tool-call turn.
    pub content: String,
    /// Tool result 的 call id。
    pub tool_call_id: Option<String>,
    /// Tool result 的 authoritative catalog name；Google functionResponse 必填。
    pub tool_name: Option<String>,
    /// Assistant tool-call blocks. Non-assistant roles must leave this empty.
    pub tool_calls: Vec<ProviderToolCall>,
}

impl core::fmt::Debug for ProviderMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .field("has_tool_call_id", &self.tool_call_id.is_some())
            .field("has_tool_name", &self.tool_name.is_some())
            .field("tool_call_count", &self.tool_calls.len())
            .finish()
    }
}

/// 权威 catalog 投影到 provider 的 function tool。
#[derive(Clone, PartialEq)]
pub struct ProviderToolDefinition {
    /// Tool name。
    pub name: String,
    /// Model-visible description。
    pub description: String,
    /// JSON Schema；application tool catalog 已先验证。
    pub input_schema: Value,
}

impl core::fmt::Debug for ProviderToolDefinition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderToolDefinition")
            .field("name", &self.name)
            .field("description_bytes", &self.description.len())
            .field("schema", &"[redacted-structure]")
            .finish()
    }
}

/// Maximum interrupts accepted from one fixed-schema terminal outcome.
pub const PROVIDER_REMOTE_INTERRUPT_MAX_ITEMS: usize = 256;
/// Maximum bytes for one remote interrupt pairing id or categorical reason.
pub const PROVIDER_REMOTE_INTERRUPT_LABEL_MAX_BYTES: usize = 256;
/// Maximum bytes retained for one optional remote presentation message.
pub const PROVIDER_REMOTE_INTERRUPT_MESSAGE_MAX_BYTES: usize = 64 * 1024;
/// Maximum encoded bytes accepted for one human resume payload.
pub const PROVIDER_REMOTE_RESUME_PAYLOAD_MAX_BYTES: usize = 64 * 1024;

/// Checked construction input for one AG-UI interrupt descriptor.
pub struct ProviderRemoteInterruptInput {
    /// Remote interrupt id; pairing only, never local authority.
    pub id: String,
    /// Remote categorical reason.
    pub reason: String,
    /// Optional user-facing remote message.
    pub message: Option<String>,
    /// Optional remote tool-call pairing id.
    pub tool_call_id: Option<String>,
    /// Optional untrusted response JSON Schema.
    pub response_schema: Option<Value>,
    /// Optional remote RFC3339-looking expiry string; database time validates it later.
    pub expires_at: Option<String>,
    /// Optional untrusted metadata object.
    pub metadata: Option<Value>,
}

/// One bounded, structurally validated AG-UI interrupt. It is deliberately non-serde.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteInterrupt {
    id: String,
    untrusted_payload: Value,
}

impl ProviderRemoteInterrupt {
    /// Normalize known 0.0.57 fields and drop all unknown remote keys.
    ///
    /// # Errors
    ///
    /// Returns a content-free error for empty/NUL labels, non-object schema/metadata, or >1 MiB.
    pub fn new(input: ProviderRemoteInterruptInput) -> Result<Self, ProviderRemoteProjectionError> {
        if [&input.id, &input.reason].into_iter().any(|value| {
            value.is_empty()
                || value.len() > PROVIDER_REMOTE_INTERRUPT_LABEL_MAX_BYTES
                || value.chars().any(char::is_control)
        }) || [
            input.message.as_deref(),
            input.tool_call_id.as_deref(),
            input.expires_at.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || input.message.as_ref().is_some_and(|value| {
                value.len() > PROVIDER_REMOTE_INTERRUPT_MESSAGE_MAX_BYTES
                    || value.chars().any(|character| {
                        character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                    })
            })
            || input.tool_call_id.as_ref().is_some_and(|value| {
                value.len() > PROVIDER_REMOTE_INTERRUPT_LABEL_MAX_BYTES
                    || value.chars().any(char::is_control)
            })
            || input
                .expires_at
                .as_ref()
                .is_some_and(|value| value.len() > 128 || value.chars().any(char::is_control))
            || input
                .response_schema
                .as_ref()
                .is_some_and(|value| !value.is_object() || value_contains_nul(value))
            || input
                .metadata
                .as_ref()
                .is_some_and(|value| !value.is_object() || value_contains_nul(value))
        {
            return Err(ProviderRemoteProjectionError::Invalid);
        }
        let mut payload = serde_json::Map::new();
        payload.insert("id".to_owned(), Value::String(input.id.clone()));
        payload.insert("reason".to_owned(), Value::String(input.reason));
        if let Some(value) = input.message {
            payload.insert("message".to_owned(), Value::String(value));
        }
        if let Some(value) = input.tool_call_id {
            payload.insert("toolCallId".to_owned(), Value::String(value));
        }
        if let Some(value) = input.response_schema {
            payload.insert("responseSchema".to_owned(), value);
        }
        if let Some(value) = input.expires_at {
            payload.insert("expiresAt".to_owned(), Value::String(value));
        }
        if let Some(value) = input.metadata {
            payload.insert("metadata".to_owned(), value);
        }
        let untrusted_payload = Value::Object(payload);
        if serde_json::to_vec(&untrusted_payload)
            .map_err(|_| ProviderRemoteProjectionError::Invalid)?
            .len()
            > PROVIDER_REMOTE_PROJECTION_MAX_BYTES
        {
            return Err(ProviderRemoteProjectionError::TooLarge);
        }
        Ok(Self {
            id: input.id,
            untrusted_payload,
        })
    }

    /// Remote pairing id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Known-field-only untrusted descriptor for durable presentation.
    #[must_use]
    pub const fn untrusted_payload(&self) -> &Value {
        &self.untrusted_payload
    }
}

impl core::fmt::Debug for ProviderRemoteInterrupt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRemoteInterrupt")
            .field("id", &self.id)
            .field("untrusted_payload", &"[redacted]")
            .finish()
    }
}

/// Non-empty interrupt outcome bound to one completed remote protocol run.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteInterruptBatch {
    protocol_run_id: String,
    interrupts: Vec<ProviderRemoteInterrupt>,
}

impl ProviderRemoteInterruptBatch {
    /// Construct an exact, unique interrupt batch.
    ///
    /// # Errors
    ///
    /// Rejects empty protocol ids, empty/oversized batches, duplicate ids, NUL, and >1 MiB.
    pub fn new(
        protocol_run_id: String,
        interrupts: Vec<ProviderRemoteInterrupt>,
    ) -> Result<Self, ProviderRemoteProjectionError> {
        if protocol_run_id.is_empty()
            || protocol_run_id.as_bytes().contains(&0)
            || protocol_run_id.len() > 1_024
            || interrupts.is_empty()
            || interrupts.len() > PROVIDER_REMOTE_INTERRUPT_MAX_ITEMS
            || interrupts
                .iter()
                .map(ProviderRemoteInterrupt::id)
                .collect::<BTreeSet<_>>()
                .len()
                != interrupts.len()
        {
            return Err(ProviderRemoteProjectionError::Invalid);
        }
        let payload = Value::Array(
            interrupts
                .iter()
                .map(|interrupt| interrupt.untrusted_payload().clone())
                .collect(),
        );
        if serde_json::to_vec(&payload)
            .map_err(|_| ProviderRemoteProjectionError::Invalid)?
            .len()
            > PROVIDER_REMOTE_PROJECTION_MAX_BYTES
        {
            return Err(ProviderRemoteProjectionError::TooLarge);
        }
        Ok(Self {
            protocol_run_id,
            interrupts,
        })
    }

    /// Protocol run that produced this terminal interrupt outcome.
    #[must_use]
    pub fn protocol_run_id(&self) -> &str {
        &self.protocol_run_id
    }

    /// Exact ordered interrupt descriptors.
    #[must_use]
    pub fn interrupts(&self) -> &[ProviderRemoteInterrupt] {
        &self.interrupts
    }
}

impl core::fmt::Debug for ProviderRemoteInterruptBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRemoteInterruptBatch")
            .field("protocol_run_id", &self.protocol_run_id)
            .field("interrupts", &self.interrupts.len())
            .finish()
    }
}

/// Closed AG-UI resume status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRemoteResumeStatus {
    /// Human supplied a resolution payload.
    Resolved,
    /// Human explicitly cancelled this interrupt.
    Cancelled,
}

impl ProviderRemoteResumeStatus {
    /// Stable 0.0.57 wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One bounded human response for a prior interrupt. It is deliberately non-serde.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteResumeEntry {
    interrupt_id: String,
    status: ProviderRemoteResumeStatus,
    payload: Option<Value>,
}

impl ProviderRemoteResumeEntry {
    /// Construct a bounded resume entry.
    ///
    /// # Errors
    ///
    /// Rejects empty/NUL ids or payloads above 64 KiB.
    pub fn new(
        interrupt_id: String,
        status: ProviderRemoteResumeStatus,
        payload: Option<Value>,
    ) -> Result<Self, ProviderRemoteProjectionError> {
        if interrupt_id.is_empty()
            || interrupt_id.len() > PROVIDER_REMOTE_INTERRUPT_LABEL_MAX_BYTES
            || interrupt_id.chars().any(char::is_control)
            || payload.as_ref().is_some_and(value_contains_nul)
        {
            return Err(ProviderRemoteProjectionError::Invalid);
        }
        if payload
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| ProviderRemoteProjectionError::Invalid)?
            .is_some_and(|value| value.len() > PROVIDER_REMOTE_RESUME_PAYLOAD_MAX_BYTES)
        {
            return Err(ProviderRemoteProjectionError::TooLarge);
        }
        Ok(Self {
            interrupt_id,
            status,
            payload,
        })
    }

    /// Interrupt pairing id.
    #[must_use]
    pub fn interrupt_id(&self) -> &str {
        &self.interrupt_id
    }

    /// Human resolution status.
    #[must_use]
    pub const fn status(&self) -> ProviderRemoteResumeStatus {
        self.status
    }

    /// Untrusted answer sent only to the remote Agent.
    #[must_use]
    pub const fn payload(&self) -> Option<&Value> {
        self.payload.as_ref()
    }

    fn wire_value(&self) -> Value {
        let mut value = serde_json::Map::new();
        value.insert(
            "interruptId".to_owned(),
            Value::String(self.interrupt_id.clone()),
        );
        value.insert(
            "status".to_owned(),
            Value::String(self.status.as_str().to_owned()),
        );
        if let Some(payload) = &self.payload {
            value.insert("payload".to_owned(), payload.clone());
        }
        Value::Object(value)
    }
}

impl core::fmt::Debug for ProviderRemoteResumeEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRemoteResumeEntry")
            .field("interrupt_id", &self.interrupt_id)
            .field("status", &self.status)
            .field("payload", &self.payload.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// A complete next-invocation resume batch with explicit AG-UI lineage.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteResume {
    parent_protocol_run_id: String,
    protocol_run_id: String,
    entries: Vec<ProviderRemoteResumeEntry>,
    wire_entries: Vec<Value>,
}

impl ProviderRemoteResume {
    /// Construct a unique, non-empty resume batch for a new protocol run id.
    ///
    /// # Errors
    ///
    /// Rejects invalid/equal run ids, empty/oversized entries, duplicate interrupt ids, or >1 MiB.
    pub fn new(
        parent_protocol_run_id: String,
        protocol_run_id: String,
        entries: Vec<ProviderRemoteResumeEntry>,
    ) -> Result<Self, ProviderRemoteProjectionError> {
        if [&parent_protocol_run_id, &protocol_run_id]
            .into_iter()
            .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || parent_protocol_run_id == protocol_run_id
            || entries.is_empty()
            || entries.len() > PROVIDER_REMOTE_INTERRUPT_MAX_ITEMS
            || entries
                .iter()
                .map(ProviderRemoteResumeEntry::interrupt_id)
                .collect::<BTreeSet<_>>()
                .len()
                != entries.len()
        {
            return Err(ProviderRemoteProjectionError::Invalid);
        }
        let wire_entries = entries
            .iter()
            .map(ProviderRemoteResumeEntry::wire_value)
            .collect::<Vec<_>>();
        if serde_json::to_vec(&wire_entries)
            .map_err(|_| ProviderRemoteProjectionError::Invalid)?
            .len()
            > PROVIDER_REMOTE_PROJECTION_MAX_BYTES
        {
            return Err(ProviderRemoteProjectionError::TooLarge);
        }
        Ok(Self {
            parent_protocol_run_id,
            protocol_run_id,
            entries,
            wire_entries,
        })
    }

    /// Previous protocol run id.
    #[must_use]
    pub fn parent_protocol_run_id(&self) -> &str {
        &self.parent_protocol_run_id
    }

    /// Fresh protocol run id for the resumed invocation.
    #[must_use]
    pub fn protocol_run_id(&self) -> &str {
        &self.protocol_run_id
    }

    /// Typed entries.
    #[must_use]
    pub fn entries(&self) -> &[ProviderRemoteResumeEntry] {
        &self.entries
    }

    /// Exact fixed-schema values encoded into `RunAgentInput.resume`.
    #[must_use]
    pub fn wire_entries(&self) -> &[Value] {
        &self.wire_entries
    }
}

impl core::fmt::Debug for ProviderRemoteResume {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRemoteResume")
            .field("parent_protocol_run_id", &self.parent_protocol_run_id)
            .field("protocol_run_id", &self.protocol_run_id)
            .field("entries", &self.entries.len())
            .finish()
    }
}

/// 一次 sampling request；actor/run/API key 不在 model request 自报面。
#[derive(Clone, Debug, PartialEq)]
pub struct ProviderRequest {
    /// Provider route from authoritative Agent configuration。
    pub route: ProviderRoute,
    /// Ordered conversation/context。
    pub messages: Vec<ProviderMessage>,
    /// Granted tools；空即 text-only。
    pub tools: Vec<ProviderToolDefinition>,
    /// Optional output token cap from authoritative budget。
    pub max_output_tokens: Option<u32>,
    /// Optional operator-attested price snapshot; `None` means explicitly unpriced, never zero.
    pub rate_card: Option<ProviderRateCard>,
    /// User cap frozen onto this run when it was created; never supplied by the model/renderer.
    pub cost_cap: Option<crate::run_cost_budget::RunCostCap>,
}

/// Maximum encoded bytes for one normalized remote projection checkpoint.
pub const PROVIDER_REMOTE_PROJECTION_MAX_BYTES: usize = 1024 * 1024;

/// Closed, non-authoritative remote projection families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRemoteProjectionKind {
    /// Current remote state after a validated snapshot or atomic RFC 6902 delta.
    State,
    /// Structurally validated remote message snapshot; never authoritative thread history.
    Messages,
    /// Current remote activity content after a snapshot or atomic delta.
    Activity,
    /// Remote step start.
    StepStarted,
    /// Remote step finish.
    StepFinished,
    /// Remote tool-result display projection; never proof that a local effect executed.
    ToolResult,
    /// Opaque RAW payload.
    Raw,
    /// Application-specific CUSTOM payload.
    Custom,
}

impl ProviderRemoteProjectionKind {
    /// Stable journal literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Messages => "messages",
            Self::Activity => "activity",
            Self::StepStarted => "step_started",
            Self::StepFinished => "step_finished",
            Self::ToolResult => "tool_result",
            Self::Raw => "raw",
            Self::Custom => "custom",
        }
    }
}

/// Stable construction failure for a remote projection; untrusted content is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderRemoteProjectionError {
    /// A required remote key was empty or any JSON key/value contained NUL.
    #[error("provider_remote_projection_invalid")]
    Invalid,
    /// The normalized checkpoint exceeded its independent one-event bound.
    #[error("provider_remote_projection_too_large")]
    TooLarge,
}

/// Stable durable remote-interrupt coordination failure; remote prose is never carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoteInterruptError {
    /// PostgreSQL/coordinator dependency is unavailable before commit is known.
    #[error("remote_interrupt_unavailable")]
    Unavailable,
    /// The active run lease, actor generation, membership, or role is no longer current.
    #[error("remote_interrupt_stale")]
    Stale,
    /// A durable identity is already bound to different content.
    #[error("remote_interrupt_conflict")]
    Conflict,
    /// Durable rows violate the closed interrupt/resume shape.
    #[error("remote_interrupt_corrupt field={field}")]
    Corrupt {
        /// Static field name only.
        field: &'static str,
    },
    /// A transaction carrying interrupt state or its audit may have committed.
    #[error("remote_interrupt_commit_unknown")]
    CommitUnknown,
}

/// Adapter construction input for one actor-visible pending remote interrupt.
pub struct RemoteInterruptPendingInput {
    /// Server-minted opaque resolution handle.
    pub request_id: String,
    /// Authoritative durable run.
    pub run_id: String,
    /// Authoritative Bot.
    pub bot_id: String,
    /// Remote protocol invocation that produced the interrupt.
    pub protocol_run_id: String,
    /// Remote pairing id; never used alone as authority.
    pub interrupt_id: String,
    /// Known-field-only untrusted descriptor.
    pub untrusted_payload: Value,
    /// Database request time.
    pub requested_at: OffsetDateTime,
    /// Local database expiry, independent from remote presentation metadata.
    pub expires_at: OffsetDateTime,
}

/// One actor-scoped pending remote interrupt for presentation. It is deliberately non-serde.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteInterruptPending {
    request_id: String,
    run_id: String,
    bot_id: String,
    protocol_run_id: String,
    interrupt_id: String,
    untrusted_payload: Value,
    requested_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl RemoteInterruptPending {
    /// Construct from a PostgreSQL row after authority filtering.
    pub fn new(input: RemoteInterruptPendingInput) -> Result<Self, RemoteInterruptError> {
        if !is_remote_interrupt_request_id(&input.request_id)
            || [&input.run_id, &input.bot_id, &input.protocol_run_id]
                .into_iter()
                .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || input.interrupt_id.is_empty()
            || input.interrupt_id.len() > PROVIDER_REMOTE_INTERRUPT_LABEL_MAX_BYTES
            || input.interrupt_id.chars().any(char::is_control)
            || !input.untrusted_payload.is_object()
            || input.untrusted_payload.get("id").and_then(Value::as_str)
                != Some(input.interrupt_id.as_str())
            || value_contains_nul(&input.untrusted_payload)
            || serde_json::to_vec(&input.untrusted_payload)
                .map_err(|_| RemoteInterruptError::Corrupt {
                    field: "interrupt_payload",
                })?
                .len()
                > PROVIDER_REMOTE_PROJECTION_MAX_BYTES
            || input.expires_at <= input.requested_at
        {
            return Err(RemoteInterruptError::Corrupt {
                field: "remote_interrupt",
            });
        }
        Ok(Self {
            request_id: input.request_id,
            run_id: input.run_id,
            bot_id: input.bot_id,
            protocol_run_id: input.protocol_run_id,
            interrupt_id: input.interrupt_id,
            untrusted_payload: input.untrusted_payload,
            requested_at: input.requested_at,
            expires_at: input.expires_at,
        })
    }

    /// Server-minted resolution handle.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Durable run id.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Authoritative Bot id.
    #[must_use]
    pub fn bot_id(&self) -> &str {
        &self.bot_id
    }

    /// Remote protocol run id.
    #[must_use]
    pub fn protocol_run_id(&self) -> &str {
        &self.protocol_run_id
    }

    /// Remote pairing id.
    #[must_use]
    pub fn interrupt_id(&self) -> &str {
        &self.interrupt_id
    }

    /// Known-field-only untrusted presentation descriptor.
    #[must_use]
    pub const fn untrusted_payload(&self) -> &Value {
        &self.untrusted_payload
    }

    /// Database request time.
    #[must_use]
    pub const fn requested_at(&self) -> OffsetDateTime {
        self.requested_at
    }

    /// Local authoritative expiry.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl core::fmt::Debug for RemoteInterruptPending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RemoteInterruptPending")
            .field("request_id", &self.request_id)
            .field("run_id", &self.run_id)
            .field("bot_id", &self.bot_id)
            .field("protocol_run_id", &self.protocol_run_id)
            .field("interrupt_id", &self.interrupt_id)
            .field("untrusted_payload", &"[redacted]")
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Durable answer acknowledgement returned only after its hash-chain audit commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteInterruptResolutionReceipt {
    request_id: String,
    status: ProviderRemoteResumeStatus,
    replayed: bool,
}

impl RemoteInterruptResolutionReceipt {
    /// Construct a checked receipt.
    pub fn new(
        request_id: String,
        status: ProviderRemoteResumeStatus,
        replayed: bool,
    ) -> Result<Self, RemoteInterruptError> {
        if !is_remote_interrupt_request_id(&request_id) {
            return Err(RemoteInterruptError::Corrupt {
                field: "request_id",
            });
        }
        Ok(Self {
            request_id,
            status,
            replayed,
        })
    }

    /// Server-minted resolution handle.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Closed wire status committed for resume.
    #[must_use]
    pub const fn status(&self) -> ProviderRemoteResumeStatus {
        self.status
    }

    /// Exact repeated answer observed without a second audit row.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Durable coordinator for one remote AG-UI interrupt batch.
///
/// Implementations must persist the batch and request audit atomically, wait on durable state,
/// revalidate actor/lease authority, and return only after every answer/expiry audit is committed.
#[async_trait]
pub trait RemoteInterruptCoordinator: Send + Sync {
    /// List current-actor pending rows after fresh role/generation/membership validation.
    async fn list_pending(
        &self,
        auth: &AuthContext,
    ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError>;

    /// Resolve one server-minted request handle and commit its audit in the same transaction.
    async fn resolve(
        &self,
        auth: &AuthContext,
        request_id: &str,
        status: ProviderRemoteResumeStatus,
        payload: Option<Value>,
    ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError>;

    /// Persist and wait for a complete typed resume batch.
    async fn persist_and_wait(
        &self,
        lease: &RunExecutionLease,
        batch: &ProviderRemoteInterruptBatch,
    ) -> Result<ProviderRemoteResume, RemoteInterruptError>;
}

/// Default fail-closed coordinator used by assemblies that have not enabled remote Agents.
#[derive(Debug, Default)]
pub struct NoRemoteInterruptCoordinator;

#[async_trait]
impl RemoteInterruptCoordinator for NoRemoteInterruptCoordinator {
    async fn list_pending(
        &self,
        _auth: &AuthContext,
    ) -> Result<Vec<RemoteInterruptPending>, RemoteInterruptError> {
        Err(RemoteInterruptError::Unavailable)
    }

    async fn resolve(
        &self,
        _auth: &AuthContext,
        _request_id: &str,
        _status: ProviderRemoteResumeStatus,
        _payload: Option<Value>,
    ) -> Result<RemoteInterruptResolutionReceipt, RemoteInterruptError> {
        Err(RemoteInterruptError::Unavailable)
    }

    async fn persist_and_wait(
        &self,
        _lease: &RunExecutionLease,
        _batch: &ProviderRemoteInterruptBatch,
    ) -> Result<ProviderRemoteResume, RemoteInterruptError> {
        Err(RemoteInterruptError::Unavailable)
    }
}

/// Bounded remote UI projection. Every remote-controlled field remains under explicit
/// `untrusted*` keys and cannot represent actor, scope, grant, decision, or local tool outcome.
#[derive(Clone, PartialEq)]
pub struct ProviderRemoteProjection {
    kind: ProviderRemoteProjectionKind,
    journal_payload: Value,
    encoded_len: usize,
}

impl ProviderRemoteProjection {
    /// Construct one projection from an already protocol-validated remote event.
    ///
    /// # Errors
    ///
    /// Returns a content-free error for empty/NUL remote keys or an encoded payload above 1 MiB.
    pub fn new(
        kind: ProviderRemoteProjectionKind,
        untrusted_key: Option<String>,
        untrusted_type: Option<String>,
        untrusted_value: Value,
    ) -> Result<Self, ProviderRemoteProjectionError> {
        if [untrusted_key.as_deref(), untrusted_type.as_deref()]
            .into_iter()
            .flatten()
            .any(|value| value.is_empty() || value.as_bytes().contains(&0))
            || value_contains_nul(&untrusted_value)
        {
            return Err(ProviderRemoteProjectionError::Invalid);
        }
        let journal_payload = json!({
            "kind":"remote_agui_projection",
            "source":"remote_ag_ui",
            "family":kind.as_str(),
            "untrusted":true,
            "untrustedKey":untrusted_key,
            "untrustedType":untrusted_type,
            "untrustedValue":untrusted_value,
        });
        let encoded_len = serde_json::to_vec(&journal_payload)
            .map_err(|_| ProviderRemoteProjectionError::Invalid)?
            .len();
        if encoded_len > PROVIDER_REMOTE_PROJECTION_MAX_BYTES {
            return Err(ProviderRemoteProjectionError::TooLarge);
        }
        Ok(Self {
            kind,
            journal_payload,
            encoded_len,
        })
    }

    /// Closed local family; it is never read from the untrusted payload.
    #[must_use]
    pub const fn kind(&self) -> ProviderRemoteProjectionKind {
        self.kind
    }

    /// Exact payload written to the operational checkpoint journal.
    #[must_use]
    pub const fn journal_payload(&self) -> &Value {
        &self.journal_payload
    }

    /// Encoded size charged to the per-session projection budget.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

impl core::fmt::Debug for ProviderRemoteProjection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProviderRemoteProjection")
            .field("kind", &self.kind)
            .field("encoded_len", &self.encoded_len)
            .field("untrusted", &"[redacted]")
            .finish()
    }
}

fn value_contains_nul(value: &Value) -> bool {
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) => {
                if value.as_bytes().contains(&0) {
                    return true;
                }
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                if values.keys().any(|key| key.as_bytes().contains(&0)) {
                    return true;
                }
                pending.extend(values.values());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    false
}

/// Provider output item kind。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutputKind {
    /// Assistant text/refusal。
    Message,
    /// Reasoning stream。
    Reasoning,
    /// Function call。
    FunctionCall,
    /// Vendor extension；accepted but not treated as a tool/effect。
    Extension,
}

/// Normalized usage。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderUsage {
    /// Input tokens。
    pub input_tokens: u64,
    /// Output tokens。
    pub output_tokens: u64,
    /// Total tokens；must equal/safely dominate known components。
    pub total_tokens: u64,
}

/// Stable provider failure category；vendor message/body never crosses this boundary。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFailure {
    /// API key/auth rejected。
    Authentication,
    /// 429；Retry-After 只保留规范化 duration，不保留 header/body。
    RateLimited {
        /// HTTP delta-seconds/date normalized against receive time。
        retry_after: Option<Duration>,
    },
    /// Explicit retryable 5xx。
    ServerUnavailable {
        /// Optional Retry-After。
        retry_after: Option<Duration>,
    },
    /// Schema/sequence/UTF-8/SSE invalid。
    InvalidResponse,
    /// Real body read gap exceeded AGENT_STALL_TIMEOUT_MS。
    StreamStalled,
    /// DNS/connect/TLS/protocol transport failure。
    Transport,
    /// Provider reported failed/incomplete output。
    GenerationFailed,
}

/// Unified normalized event（v3 §7.3）。
#[derive(Clone, PartialEq)]
pub enum ProviderEvent {
    /// Response identity became available。
    ResponseStarted {
        /// Vendor response id；只作 trace/correlation，不作授权。
        response_id: String,
    },
    /// Skeleton item；name/arguments may arrive later。
    OutputItemAdded {
        /// Stable output index。
        index: u32,
        /// Normalized item kind。
        kind: ProviderOutputKind,
    },
    /// Text/refusal delta。
    TextDelta {
        /// Output index。
        index: u32,
        /// Complete UTF-8 delta。
        delta: String,
    },
    /// Reasoning delta。
    ReasoningDelta {
        /// Output index。
        index: u32,
        /// Complete UTF-8 delta。
        delta: String,
    },
    /// Bounded AG-UI state/progress/display data, explicitly non-authoritative.
    RemoteProjection(ProviderRemoteProjection),
    /// Remote protocol run reached a durable human interrupt outcome.
    Interrupted(ProviderRemoteInterruptBatch),
    /// Tool skeleton。
    ToolCallStarted {
        /// Stable output/tool index。
        index: u32,
        /// Provider call id。
        call_id: String,
        /// Name may arrive later。
        name: Option<String>,
    },
    /// Partial JSON string。
    ToolArgumentsDelta {
        /// Stable output/tool index。
        index: u32,
        /// Provider call id。
        call_id: String,
        /// Partial JSON string。
        delta: String,
    },
    /// Complete parsed arguments。
    ToolCallCompleted {
        /// Stable output/tool index。
        index: u32,
        /// Provider call id。
        call_id: String,
        /// Final tool name。
        name: String,
        /// Parsed JSON object arguments。
        arguments: Value,
    },
    /// Token usage。
    Usage(ProviderUsage),
    /// Exactly one normal terminal from provider stream。
    Completed,
    /// Exactly one normalized failure terminal。
    Failed(ProviderFailure),
}

impl core::fmt::Debug for ProviderEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ResponseStarted { response_id } => f
                .debug_struct("ResponseStarted")
                .field("response_id", response_id)
                .finish(),
            Self::OutputItemAdded { index, kind } => f
                .debug_struct("OutputItemAdded")
                .field("index", index)
                .field("kind", kind)
                .finish(),
            Self::TextDelta { index, delta } => f
                .debug_struct("TextDelta")
                .field("index", index)
                .field("bytes", &delta.len())
                .finish(),
            Self::ReasoningDelta { index, delta } => f
                .debug_struct("ReasoningDelta")
                .field("index", index)
                .field("bytes", &delta.len())
                .finish(),
            Self::RemoteProjection(projection) => {
                f.debug_tuple("RemoteProjection").field(projection).finish()
            }
            Self::Interrupted(interrupts) => {
                f.debug_tuple("Interrupted").field(interrupts).finish()
            }
            Self::ToolCallStarted {
                index,
                call_id,
                name,
            } => f
                .debug_struct("ToolCallStarted")
                .field("index", index)
                .field("call_id", call_id)
                .field("name", name)
                .finish(),
            Self::ToolArgumentsDelta {
                index,
                call_id,
                delta,
            } => f
                .debug_struct("ToolArgumentsDelta")
                .field("index", index)
                .field("call_id", call_id)
                .field("bytes", &delta.len())
                .finish(),
            Self::ToolCallCompleted {
                index,
                call_id,
                name,
                ..
            } => f
                .debug_struct("ToolCallCompleted")
                .field("index", index)
                .field("call_id", call_id)
                .field("name", name)
                .field("arguments", &"[redacted]")
                .finish(),
            Self::Usage(usage) => f.debug_tuple("Usage").field(usage).finish(),
            Self::Completed => f.write_str("Completed"),
            Self::Failed(failure) => f.debug_tuple("Failed").field(failure).finish(),
        }
    }
}

/// Provider start/stream transport error；在 event terminal 之前发生。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProviderPortError {
    /// Config/request invalid before network。
    #[error("provider_request_invalid field={field}")]
    InvalidRequest {
        /// Static field。
        field: &'static str,
    },
    /// Transport/status unavailable；细分类由 returned Failed event 表达时可用。
    #[error("provider_unavailable")]
    Unavailable,
    /// Request may have left the process before headers became knowable；不得自动重试。
    #[error("provider_commit_unknown")]
    CommitUnknown,
}

/// Provider 对本次停止请求的观察结果；不承诺停止前没有外部副作用。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// 已观察到远端在该时刻停止产生新工作。
    Confirmed {
        /// Adapter 观察到的停止时刻，仅用于诊断。
        at: SystemTime,
    },
    /// 无法确认远端已停止。
    Unknown,
    /// 没有远端停止能力，保留丢弃本地流的原行为。
    Unsupported,
}

/// 一条已打开的 provider stream。
#[async_trait]
pub trait ProviderSession: Send {
    /// 下一 normalized event；`None` 只允许发生在 terminal event 之后。
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError>;

    /// 请求停止；调用方限制等待期限。默认实现没有 I/O 或等待。
    async fn request_stop(&mut self) -> Result<StopOutcome, ProviderPortError> {
        Ok(StopOutcome::Unsupported)
    }
}

/// Built-in Agent sampling port。
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    /// Start sampling；API key/endpoint/model 由 adapter verified config 持有。
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError>;
}

/// Authoritative thread/Bot context load failure。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentContextError {
    /// PostgreSQL unavailable。
    #[error("agent_context_unavailable")]
    Unavailable,
    /// Run/thread/membership/fencing no longer visible。
    #[error("agent_context_stale")]
    Stale,
    /// Stored row malformed。
    #[error("agent_context_corrupt field={field}")]
    Corrupt {
        /// Static field。
        field: &'static str,
    },
    /// Context exceeds the bounded first slice; compression is not silently faked。
    #[error("agent_context_too_large")]
    TooLarge,
    /// Existing tool history ends with an unfinished assistant/tool pair.
    #[error("agent_context_tool_history_unsupported")]
    ToolHistoryUnsupported,
}

/// PostgreSQL context/catalog projection port for a verified run lease。
#[async_trait]
pub trait AgentContextSource: Send + Sync {
    /// Load provider-neutral request；scope must be revalidated in the query。
    async fn load(&self, lease: &RunExecutionLease) -> Result<ProviderRequest, AgentContextError>;
}

/// Built-in Agent lifecycle audit facts；不携带 prompt/delta/key/vendor body。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentAuditKind {
    /// Dispatch 已 durable activate、即将读取 context。
    Invoked,
    /// Provider real body read gap exceeded the configured watchdog。
    StreamStalled,
    /// Absolute run deadline fired after child cancellation。
    RunDeadlineExceeded,
    /// Frozen cap has no operator-attested rate snapshot.
    RunCostBudgetUnpriced,
    /// Frozen cap and operator-attested rate use different currencies.
    RunCostBudgetCurrencyMismatch,
    /// Durable cost upper bound exceeded the frozen cap.
    RunCostBudgetExceeded,
}

/// Audit chain append failure；底层错误不跨 Agent boundary。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentAuditError {
    /// PostgreSQL/hash-chain unavailable or commit unknown。
    #[error("agent_audit_unavailable")]
    Unavailable,
}

/// Agent lifecycle audit port；production 必须注入 hash-chain implementation。
#[async_trait]
pub trait AgentAudit: Send + Sync {
    /// Append one allowlisted lifecycle fact for the authoritative lease。
    async fn record(
        &self,
        lease: &RunExecutionLease,
        kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError>;
}

/// Explicit no-op used by narrow unit/integration harnesses；production main never constructs it。
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAgentAudit;

#[async_trait]
impl AgentAudit for NoAgentAudit {
    async fn record(
        &self,
        _lease: &RunExecutionLease,
        _kind: AgentAuditKind,
    ) -> Result<(), AgentAuditError> {
        Ok(())
    }
}

#[cfg(test)]
mod remote_projection_tests {
    use std::collections::BTreeSet;

    use super::*;

    fn interrupt(id: &str) -> ProviderRemoteInterrupt {
        ProviderRemoteInterrupt::new(ProviderRemoteInterruptInput {
            id: id.to_owned(),
            reason: "confirmation".to_owned(),
            message: Some("REMOTE_INTERRUPT_MESSAGE_CANARY".to_owned()),
            tool_call_id: Some("call-1".to_owned()),
            response_schema: Some(json!({"type":"object"})),
            expires_at: Some("2026-09-04T12:00:00Z".to_owned()),
            metadata: Some(json!({"remote":"untrusted"})),
        })
        .unwrap()
    }

    #[test]
    fn closed_families_are_unique_and_payload_is_explicitly_untrusted() {
        let kinds = [
            ProviderRemoteProjectionKind::State,
            ProviderRemoteProjectionKind::Messages,
            ProviderRemoteProjectionKind::Activity,
            ProviderRemoteProjectionKind::StepStarted,
            ProviderRemoteProjectionKind::StepFinished,
            ProviderRemoteProjectionKind::ToolResult,
            ProviderRemoteProjectionKind::Raw,
            ProviderRemoteProjectionKind::Custom,
        ];
        assert_eq!(
            kinds
                .into_iter()
                .map(ProviderRemoteProjectionKind::as_str)
                .collect::<BTreeSet<_>>()
                .len(),
            kinds.len()
        );
        let projection = ProviderRemoteProjection::new(
            ProviderRemoteProjectionKind::Raw,
            Some("remote-source".to_owned()),
            None,
            json!({"actor":"forged-admin","permission":"grant","canary":"SECRET_VALUE"}),
        )
        .unwrap();
        assert_eq!(projection.kind(), ProviderRemoteProjectionKind::Raw);
        assert_eq!(projection.journal_payload()["untrusted"], true);
        assert_eq!(projection.journal_payload()["source"], "remote_ag_ui");
        assert_eq!(
            projection.journal_payload()["family"],
            ProviderRemoteProjectionKind::Raw.as_str()
        );
        assert_eq!(
            projection.journal_payload()["untrustedKey"],
            "remote-source"
        );
        assert!(projection.encoded_len() <= PROVIDER_REMOTE_PROJECTION_MAX_BYTES);
        assert!(!format!("{projection:?}").contains("SECRET_VALUE"));
        assert!(!projection.journal_payload().get("actor").is_some());
    }

    #[test]
    fn empty_nul_and_oversized_projection_inputs_fail_closed() {
        assert_eq!(
            ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::StepStarted,
                Some(String::new()),
                None,
                Value::Null,
            ),
            Err(ProviderRemoteProjectionError::Invalid)
        );
        assert_eq!(
            ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::Custom,
                Some("event".to_owned()),
                None,
                json!({"nested":[{"bad":"nul\0value"}]}),
            ),
            Err(ProviderRemoteProjectionError::Invalid)
        );
        assert_eq!(
            ProviderRemoteProjection::new(
                ProviderRemoteProjectionKind::Raw,
                None,
                None,
                Value::String("x".repeat(PROVIDER_REMOTE_PROJECTION_MAX_BYTES)),
            ),
            Err(ProviderRemoteProjectionError::TooLarge)
        );
    }

    #[test]
    fn interrupt_resume_is_unique_bounded_and_keeps_local_run_authority() {
        let interrupt = interrupt("interrupt-1");
        assert_eq!(interrupt.id(), "interrupt-1");
        assert_eq!(interrupt.untrusted_payload()["reason"], "confirmation");
        assert!(!format!("{interrupt:?}").contains("REMOTE_INTERRUPT_MESSAGE_CANARY"));
        assert_eq!(
            ProviderRemoteInterruptBatch::new(
                "protocol-run-1".to_owned(),
                vec![interrupt.clone(), interrupt.clone()],
            ),
            Err(ProviderRemoteProjectionError::Invalid)
        );
        let batch = ProviderRemoteInterruptBatch::new("protocol-run-1".to_owned(), vec![interrupt])
            .unwrap();
        assert_eq!(batch.interrupts().len(), 1);

        let entry = ProviderRemoteResumeEntry::new(
            "interrupt-1".to_owned(),
            ProviderRemoteResumeStatus::Resolved,
            Some(json!({"approved":true,"canary":"REMOTE_RESUME_PAYLOAD_CANARY"})),
        )
        .unwrap();
        let resume = ProviderRemoteResume::new(
            "protocol-run-1".to_owned(),
            "protocol-run-2".to_owned(),
            vec![entry],
        )
        .unwrap();
        assert_eq!(resume.entries().len(), 1);
        assert_eq!(resume.wire_entries()[0]["status"], "resolved");
        assert!(!format!("{resume:?}").contains("REMOTE_RESUME_PAYLOAD_CANARY"));

        let route = RemoteAguiRoute::new(
            "https://agent.example/run".to_owned(),
            "thread-1".to_owned(),
            "protocol-run-1".to_owned(),
            "bot-1".to_owned(),
            Some("assertion".to_owned()),
        )
        .unwrap()
        .with_resume(resume)
        .unwrap();
        assert_eq!(route.local_run_id(), "protocol-run-1");
        assert_eq!(route.run_id(), "protocol-run-2");
        assert_eq!(route.parent_protocol_run_id(), Some("protocol-run-1"));
        assert_eq!(route.resume().unwrap().entries().len(), 1);
    }

    #[test]
    fn resume_rejects_duplicate_ids_wrong_lineage_and_oversized_payload() {
        let entry = ProviderRemoteResumeEntry::new(
            "interrupt-1".to_owned(),
            ProviderRemoteResumeStatus::Cancelled,
            None,
        )
        .unwrap();
        assert_eq!(
            ProviderRemoteResume::new(
                "run-1".to_owned(),
                "run-2".to_owned(),
                vec![entry.clone(), entry],
            ),
            Err(ProviderRemoteProjectionError::Invalid)
        );
        assert_eq!(
            ProviderRemoteResumeEntry::new(
                "interrupt-1".to_owned(),
                ProviderRemoteResumeStatus::Resolved,
                Some(Value::String(
                    "x".repeat(PROVIDER_REMOTE_RESUME_PAYLOAD_MAX_BYTES + 1),
                )),
            ),
            Err(ProviderRemoteProjectionError::TooLarge)
        );
        let resume = ProviderRemoteResume::new(
            "other-parent".to_owned(),
            "run-2".to_owned(),
            vec![
                ProviderRemoteResumeEntry::new(
                    "interrupt-1".to_owned(),
                    ProviderRemoteResumeStatus::Cancelled,
                    None,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert!(matches!(
            RemoteAguiRoute::new(
                "https://agent.example/run".to_owned(),
                "thread-1".to_owned(),
                "run-1".to_owned(),
                "bot-1".to_owned(),
                Some("assertion".to_owned()),
            )
            .unwrap()
            .with_resume(resume),
            Err(AgentContextError::Corrupt {
                field: "remote_resume_parent"
            })
        ));
    }
}

#[cfg(test)]
#[path = "provider_stop_tests.rs"]
mod stop_tests;

#[cfg(test)]
mod rate_card_tests {
    use super::*;
    use time::macros::datetime;

    fn card(input: u64, output: u64) -> ProviderRateCard {
        ProviderRateCard::new(ProviderRateCardInput {
            family: ProviderBillingFamily::OpenAiCompatible,
            model: "model-1".to_owned(),
            currency: "USD".to_owned(),
            max_input_micro_units_per_million_tokens: input,
            max_output_micro_units_per_million_tokens: output,
            source_url: "https://prices.example.test/archive/2026-08-30".to_owned(),
            source_sha256: "a".repeat(64),
            observed_at: datetime!(2026-08-30 12:00 UTC),
        })
        .unwrap()
    }

    #[test]
    fn explicit_provenance_is_closed_and_credential_free() {
        let rate = card(1_500_000, 2_000_000);
        assert_eq!(rate.family().as_str(), "openai_compatible");
        assert_eq!(rate.model(), "model-1");
        assert_eq!(rate.currency(), "USD");
        assert_eq!(rate.source_sha256(), "a".repeat(64));
        assert_eq!(rate.observed_at(), datetime!(2026-08-30 12:00 UTC));
        let bad_currency = ProviderRateCardInput {
            family: ProviderBillingFamily::OpenAiCompatible,
            model: "model-1".to_owned(),
            currency: "usd".to_owned(),
            max_input_micro_units_per_million_tokens: 1,
            max_output_micro_units_per_million_tokens: 1,
            source_url: "https://prices.example.test/rates".to_owned(),
            source_sha256: "a".repeat(64),
            observed_at: datetime!(2026-08-30 12:00 UTC),
        };
        assert_eq!(
            ProviderRateCard::new(bad_currency),
            Err(ProviderRateCardError::Currency),
        );
        for source in [
            "http://prices.example.test/rates",
            "https://user@prices.example.test/rates",
            "https://prices.example.test/rates?contract=secret",
            "https://prices.example.test/rates#today",
        ] {
            assert_eq!(
                ProviderRateCard::new(ProviderRateCardInput {
                    family: ProviderBillingFamily::Anthropic,
                    model: "model-1".to_owned(),
                    currency: "USD".to_owned(),
                    max_input_micro_units_per_million_tokens: 1,
                    max_output_micro_units_per_million_tokens: 1,
                    source_url: source.to_owned(),
                    source_sha256: "a".repeat(64),
                    observed_at: datetime!(2026-08-30 12:00 UTC),
                }),
                Err(ProviderRateCardError::Source),
            );
        }
        assert_eq!(
            ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::Google,
                model: "model-1".to_owned(),
                currency: "USD".to_owned(),
                max_input_micro_units_per_million_tokens: 1,
                max_output_micro_units_per_million_tokens: 1,
                source_url: "https://prices.example.test/rates".to_owned(),
                source_sha256: "A".repeat(64),
                observed_at: datetime!(2026-08-30 12:00 UTC),
            }),
            Err(ProviderRateCardError::Digest),
        );
    }

    #[test]
    fn exact_cost_carries_fraction_across_samplings_before_rounding() {
        let rate = card(1_500_000, 2_000_000);
        let one = ProviderCostUpperBound::default()
            .accrue(
                ProviderUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                },
                &rate,
            )
            .unwrap();
        assert_eq!(one.micro_units(), 3);
        assert_eq!(one.remainder_millionths(), 500_000);
        assert_eq!(one.billed_upper_bound_micro_units(), Some(4));
        let two = one
            .accrue(
                ProviderUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                },
                &rate,
            )
            .unwrap();
        assert_eq!(two.micro_units(), 7);
        assert_eq!(two.remainder_millionths(), 0);
        assert_eq!(two.billed_upper_bound_micro_units(), Some(7));
    }

    #[test]
    fn arithmetic_overflow_and_invalid_durable_parts_fail_closed() {
        assert_eq!(
            ProviderCostUpperBound::from_parts(0, 1_000_000),
            Err(ProviderRateCardError::Rate),
        );
        assert_eq!(
            ProviderCostUpperBound::default().accrue(
                ProviderUsage {
                    input_tokens: u64::MAX,
                    output_tokens: u64::MAX,
                    total_tokens: u64::MAX,
                },
                &card(i64::MAX as u64, i64::MAX as u64),
            ),
            Err(ProviderRateCardError::Rate),
        );
    }
}
