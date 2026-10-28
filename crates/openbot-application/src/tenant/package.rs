//! Tenant Package 五份 YAML 的纯解析、受众校验与同步 port（v3 §3.2 / §6.5）。
//!
//! 文件读取、checksum 与 PostgreSQL 事务属于 infra；本模块只接收已经读入的文本和显式环境
//! 投影。GUI 第一真源规定 design token 只能来自 `wrokbot-ui/design/tokens.toml`，因此 runtime
//! tenant CSS 不在输入类型里；历史 `skin.stylesheet` 只产生兼容状态，不读取、更不执行。

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use openbot_contracts::ids::{ActorId, ChannelId};
use openbot_contracts::text::trim_ecmascript;
use openbot_domain::identity::groups::{
    AudienceNote, AudienceValidationError, ChannelAudience, DeploymentMode, IdentityProviderId,
    IdpGroupMapping, validate_audience,
};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::ProviderExtensionKey;
use crate::provider::{ProviderBillingFamily, ProviderRateCard, ProviderRateCardInput};

/// Tenant Package 唯一允许读取的五个文件；runtime `theme.css` 刻意不在其中。
pub const TENANT_PACKAGE_FILENAMES: [&str; 5] = [
    "brand.yaml",
    "agents.yaml",
    "channels.yaml",
    "model.yaml",
    "knowledge.yaml",
];

/// Example/legacy managed endpoint 的内部 in-process sentinel；绝不作为 URL 发出网络请求。
pub const MANAGED_AGENT_IN_PROCESS_ENDPOINT: &str = "openbot-internal://managed-agent";

/// 会出现在稳定错误里的文件标识。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantPackageFile {
    /// `brand.yaml`。
    Brand,
    /// `agents.yaml`。
    Agents,
    /// `channels.yaml`。
    Channels,
    /// `model.yaml`。
    Model,
    /// `knowledge.yaml`。
    Knowledge,
}

impl TenantPackageFile {
    /// 固定文件名。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Brand => "brand.yaml",
            Self::Agents => "agents.yaml",
            Self::Channels => "channels.yaml",
            Self::Model => "model.yaml",
            Self::Knowledge => "knowledge.yaml",
        }
    }
}

/// 五份已经读取、完成环境展开的 YAML 文本。
pub struct TenantPackageFiles {
    /// `brand.yaml` 文本。
    pub brand: String,
    /// `agents.yaml` 文本。
    pub agents: String,
    /// `channels.yaml` 文本。
    pub channels: String,
    /// `model.yaml` 文本。
    pub model: String,
    /// `knowledge.yaml` 文本。
    pub knowledge: String,
}

/// Tenant Package 解析/环境展开失败；不保存 YAML 原文或环境变量值。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantPackageError {
    /// YAML 不是所需的封闭 schema。
    #[error("tenant_package_yaml_invalid file={file:?}")]
    YamlInvalid {
        /// 出错文件。
        file: TenantPackageFile,
    },
    /// 必填字符串缺失或按 ECMAScript TrimString 后为空。
    #[error("tenant_package_required_string field={field}")]
    RequiredString {
        /// 静态 schema 字段名。
        field: &'static str,
    },
    /// 列表/对象等字段形状不成立。
    #[error("tenant_package_shape_invalid field={field}")]
    ShapeInvalid {
        /// 静态 schema 字段名。
        field: &'static str,
    },
    /// Agent 类型不在 `built-in|remote-ag-ui` 封闭集合。
    #[error("tenant_package_agent_type_invalid")]
    AgentTypeInvalid,
    /// Agent id 与 deployment route 精确冲突。
    #[error("tenant_package_agent_id_reserved")]
    AgentIdReserved,
    /// Agent id 在同一包内重复。
    #[error("tenant_package_agent_id_duplicate")]
    AgentIdDuplicate,
    /// Channel id 在同一包内重复。
    #[error("tenant_package_channel_id_duplicate")]
    ChannelIdDuplicate,
    /// Channel 引用了包里不存在且未因空 endpoint 被省略的 Agent。
    #[error("tenant_package_channel_agent_unknown")]
    ChannelAgentUnknown,
    /// `allowed_groups` 为空或含空组名。
    #[error("{code}")]
    AudienceInvalid {
        /// 领域层稳定 code。
        code: &'static str,
    },
    /// model provider 不是第一真源首版固定的 OpenAI adapter。
    #[error("tenant_package_model_provider_unsupported")]
    ModelProviderUnsupported,
    /// knowledge source 类型不在兼容输入集合。
    #[error("tenant_package_knowledge_source_unsupported")]
    KnowledgeSourceUnsupported,
    /// 环境占位符无非空值且没有默认值。
    #[error("tenant_package_environment_missing file={file:?} name={name}")]
    EnvironmentMissing {
        /// 引用变量的文件。
        file: TenantPackageFile,
        /// 变量名；解析器只接受 ASCII identifier，不含值。
        name: String,
    },
    /// Loaded package 的 source/checksum 元数据形状不成立。
    #[error("tenant_package_loaded_metadata_invalid")]
    LoadedMetadataInvalid,
    /// audience context 本身不一致。
    #[error("tenant_package_audience_context_invalid")]
    AudienceContextInvalid,
    /// 对外 brand 复用了第一真源禁止的项目/厂商标记。
    #[error("tenant_package_brand_restricted")]
    BrandRestricted,
}

impl TenantPackageError {
    /// 稳定错误码。
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::YamlInvalid { .. } => "tenant_package_yaml_invalid",
            Self::RequiredString { .. } => "tenant_package_required_string",
            Self::ShapeInvalid { .. } => "tenant_package_shape_invalid",
            Self::AgentTypeInvalid => "tenant_package_agent_type_invalid",
            Self::AgentIdReserved => "tenant_package_agent_id_reserved",
            Self::AgentIdDuplicate => "tenant_package_agent_id_duplicate",
            Self::ChannelIdDuplicate => "tenant_package_channel_id_duplicate",
            Self::ChannelAgentUnknown => "tenant_package_channel_agent_unknown",
            Self::AudienceInvalid { code } => code,
            Self::ModelProviderUnsupported => "tenant_package_model_provider_unsupported",
            Self::KnowledgeSourceUnsupported => "tenant_package_knowledge_source_unsupported",
            Self::EnvironmentMissing { .. } => "tenant_package_environment_missing",
            Self::LoadedMetadataInvalid => "tenant_package_loaded_metadata_invalid",
            Self::AudienceContextInvalid => "tenant_package_audience_context_invalid",
            Self::BrandRestricted => "tenant_package_brand_restricted",
        }
    }
}

/// 只向包展开器暴露的显式环境投影。
///
/// Server 必须从完整进程环境中挑选安全 allowlist 后构造；Debug 只显示变量名，不显示值。
#[derive(Clone, Default)]
pub struct TenantPackageEnvironment {
    values: BTreeMap<String, String>,
}

impl TenantPackageEnvironment {
    /// 调用方把给定映射中的每个名字都显式批准为包输入。
    #[must_use]
    pub fn from_explicit(values: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    /// 从更大的环境映射中只投影 allowlist 名字。
    #[must_use]
    pub fn from_allowlist(source: &BTreeMap<String, String>, allowed: &[&str]) -> Self {
        let values = allowed
            .iter()
            .filter_map(|name| {
                source
                    .get(*name)
                    .map(|value| ((*name).to_owned(), value.clone()))
            })
            .collect();
        Self { values }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

impl core::fmt::Debug for TenantPackageEnvironment {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TenantPackageEnvironment")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

/// 展开 `${NAME}` / `${NAME:-fallback}`；替换值不做递归展开。
///
/// # Errors
///
/// 合法变量名无值且无默认值时返回 [`TenantPackageError::EnvironmentMissing`]。
pub fn expand_environment(
    input: &str,
    file: TenantPackageFile,
    environment: &TenantPackageEnvironment,
) -> Result<String, TenantPackageError> {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(relative) = input[cursor..].find("${") {
        let start = cursor + relative;
        output.push_str(&input[cursor..start]);
        let content_start = start + 2;
        let Some(close_relative) = input[content_start..].find('}') else {
            output.push_str(&input[start..]);
            return Ok(output);
        };
        let end = content_start + close_relative;
        let content = &input[content_start..end];
        let (name, fallback) = content
            .split_once(":-")
            .map_or((content, None), |(name, fallback)| (name, Some(fallback)));
        if !valid_environment_name(name) {
            output.push_str(&input[start..=end]);
            cursor = end + 1;
            continue;
        }
        match environment.get(name).filter(|value| !value.is_empty()) {
            Some(value) => output.push_str(value),
            None => match fallback {
                Some(value) => output.push_str(value),
                None => {
                    return Err(TenantPackageError::EnvironmentMissing {
                        file,
                        name: name.to_owned(),
                    });
                }
            },
        }
        cursor = end + 1;
    }
    output.push_str(&input[cursor..]);
    Ok(output)
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Tenant runtime theme 的兼容处置；CSS 内容永远不进入此类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantThemeStatus {
    /// 包未声明旧 `skin.stylesheet`。
    Absent,
    /// 旧字段被识别，但 GUI 只使用项目 design tokens，因此不读取/应用对应 CSS。
    CompatibilityInputIgnored,
}

impl TenantThemeStatus {
    /// 稳定状态码；不是 UI 文案。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::CompatibilityInputIgnored => "compatibility_input_ignored",
        }
    }
}

/// Agent 的封闭运行类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantAgentType {
    /// 第一方 Rust built-in Agent。
    BuiltIn,
    /// 用户提供的 remote AG-UI Agent。
    RemoteAgUi,
}

impl TenantAgentType {
    /// PostgreSQL enum 使用的稳定值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built_in",
            Self::RemoteAgUi => "remote_ag_ui",
        }
    }
}

/// Agent 的类型化配置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantAgentConfiguration {
    /// built-in Agent system prompt。
    BuiltIn {
        /// 系统提示。
        system_prompt: String,
        /// Package model 或 deployment managed provider。
        provider_source: BuiltInProviderSource,
    },
    /// remote AG-UI endpoint。
    RemoteAgUi {
        /// 展开后的 endpoint。
        endpoint: String,
    },
}

/// Built-in Agent 的权威 provider 选择层（v3 §7.3）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuiltInProviderSource {
    /// `model.yaml` 固定 OpenAI。
    Package,
    /// Deployment `BOT_PROVIDER/BOT_MODEL` managed slot。
    Managed,
    /// Assembly-registered provider extension, declared as `providerSource: extension:<key>`.
    Extension(ProviderExtensionKey),
}

impl BuiltInProviderSource {
    /// PostgreSQL Agent configuration 的稳定字面量；extension 原样为 `extension:<key>`。
    #[must_use]
    pub fn as_str(&self) -> Cow<'static, str> {
        match self {
            Self::Package => Cow::Borrowed("package"),
            Self::Managed => Cow::Borrowed("managed"),
            Self::Extension(key) => Cow::Owned(format!("extension:{}", key.as_str())),
        }
    }
}

/// 包声明的一个 Agent。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantAgent {
    /// 稳定 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// UI 标题。
    pub title: String,
    /// 角色说明。
    pub role_description: String,
    /// 可选头像 seed；持久化时缺省回落到 id。
    pub avatar_seed: Option<String>,
    /// 运行类型。
    pub agent_type: TenantAgentType,
    /// 类型化配置。
    pub configuration: TenantAgentConfiguration,
}

/// 包声明的一个 Channel。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantChannel {
    /// 稳定 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// 说明。
    pub description: String,
    /// 允许参与的 Agent id，已过滤被省略的空 endpoint remote Agent。
    pub permitted_agents: Vec<String>,
    /// 原始 `allowed_groups`，用于 PostgreSQL 兼容列。
    pub allowed_groups: Vec<String>,
    /// 领域层解析后的受众。
    pub audience: ChannelAudience,
}

/// 固定 model 配置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantModel {
    /// provider；首版恒为 `openai`。
    pub provider: String,
    /// vault secret reference，不是 secret 本体。
    pub credential_secret_ref: String,
    /// 默认模型 id。
    pub default_model: String,
    /// Optional operator-attested rate snapshot; absence remains explicitly unpriced.
    pub rate_card: Option<ProviderRateCard>,
}

/// 兼容解析但不执行本地索引的 knowledge source。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantKnowledgeSource {
    /// `google-drive|microsoft-onedrive`。
    pub source_type: String,
    /// 兼容 roots 输入。
    pub roots: Vec<String>,
}

/// 通过纯 schema/reference 校验的 Tenant Package。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantPackage {
    /// 租户 id。
    pub tenant_id: String,
    /// 对外产品名。
    pub product_name: String,
    /// runtime theme 兼容处置。
    pub theme_status: TenantThemeStatus,
    /// Agents。
    pub agents: Vec<TenantAgent>,
    /// Channels。
    pub channels: Vec<TenantChannel>,
    /// Model 配置。
    pub model: TenantModel,
    /// 兼容解析、明确不执行本地索引的 knowledge sources。
    pub knowledge_sources: Vec<TenantKnowledgeSource>,
}

/// 校验五份 YAML，并做 Agent/Channel 引用与三档 audience 结构校验。
///
/// # Errors
///
/// 任何 schema、必填值、引用、保留名或 audience 结构错误都会返回稳定错误；不回显 YAML。
pub fn validate_tenant_package(
    files: TenantPackageFiles,
) -> Result<TenantPackage, TenantPackageError> {
    let brand: RawBrand = parse_yaml(&files.brand, TenantPackageFile::Brand)?;
    let agents_file: RawAgents = parse_yaml(&files.agents, TenantPackageFile::Agents)?;
    let channels_file: RawChannels = parse_yaml(&files.channels, TenantPackageFile::Channels)?;
    let model_file: RawModelFile = parse_yaml(&files.model, TenantPackageFile::Model)?;
    let knowledge_file: RawKnowledge = parse_yaml(&files.knowledge, TenantPackageFile::Knowledge)?;

    let tenant_id = required(Some(brand.tenant.id), "tenant.id")?;
    let product_name = required(Some(brand.tenant.product_name), "tenant.product_name")?;
    validate_public_brand(&tenant_id, &product_name)?;
    let theme_status = match brand.skin {
        Some(skin) => {
            required(Some(skin.stylesheet), "skin.stylesheet")?;
            TenantThemeStatus::CompatibilityInputIgnored
        }
        None => TenantThemeStatus::Absent,
    };

    let mut omitted = BTreeSet::new();
    let mut agent_ids = BTreeSet::new();
    let mut agents = Vec::new();
    for raw in agents_file.agents {
        let mut agent_type = match raw.agent_type.as_deref() {
            Some("built-in") => TenantAgentType::BuiltIn,
            Some("remote-ag-ui") => TenantAgentType::RemoteAgUi,
            _ => return Err(TenantPackageError::AgentTypeInvalid),
        };
        let id = required(raw.id, "agent.id")?;
        if ["fleet", "policy"].contains(&id.as_str()) {
            return Err(TenantPackageError::AgentIdReserved);
        }
        if agent_type == TenantAgentType::RemoteAgUi
            && raw
                .endpoint
                .as_deref()
                .is_none_or(|value| trim_ecmascript(value).is_empty())
        {
            omitted.insert(id);
            continue;
        }
        if !agent_ids.insert(id.clone()) {
            return Err(TenantPackageError::AgentIdDuplicate);
        }
        let name = required(raw.name, "agent.name")?;
        let title = required(raw.title, "agent.title")?;
        let role_description = required(raw.role_description, "agent.role_description")?;
        let avatar_seed = raw
            .avatar_seed
            .map(|value| required(Some(value), "agent.avatar_seed"))
            .transpose()?;
        let managed_in_process = agent_type == TenantAgentType::RemoteAgUi
            && raw.endpoint.as_deref() == Some(MANAGED_AGENT_IN_PROCESS_ENDPOINT);
        let configuration = match (agent_type, managed_in_process) {
            (TenantAgentType::BuiltIn, false) => TenantAgentConfiguration::BuiltIn {
                system_prompt: required(raw.system_prompt, "agent.system_prompt")?,
                provider_source: match raw.provider_source.as_deref() {
                    None => BuiltInProviderSource::Package,
                    Some(value) => value
                        .strip_prefix("extension:")
                        .and_then(|key| ProviderExtensionKey::new(key).ok())
                        .map(BuiltInProviderSource::Extension)
                        .ok_or(TenantPackageError::ShapeInvalid {
                            field: "agent.providerSource",
                        })?,
                },
            },
            (TenantAgentType::RemoteAgUi, true) => {
                agent_type = TenantAgentType::BuiltIn;
                TenantAgentConfiguration::BuiltIn {
                    system_prompt: managed_standing_prompt(&name, &title, &role_description),
                    provider_source: BuiltInProviderSource::Managed,
                }
            }
            (TenantAgentType::RemoteAgUi, false) => TenantAgentConfiguration::RemoteAgUi {
                endpoint: required(raw.endpoint, "agent.endpoint")?,
            },
            (TenantAgentType::BuiltIn, true) => unreachable!("managed sentinel starts remote"),
        };
        agents.push(TenantAgent {
            id,
            name,
            title,
            role_description,
            avatar_seed,
            agent_type,
            configuration,
        });
    }

    let mut channel_ids = BTreeSet::new();
    let mut channels = Vec::new();
    for raw in channels_file.channels {
        let id = required(raw.id, "channel.id")?;
        if !channel_ids.insert(id.clone()) {
            return Err(TenantPackageError::ChannelIdDuplicate);
        }
        let permitted_agents = raw
            .permitted_agents
            .ok_or(TenantPackageError::ShapeInvalid {
                field: "channel.permitted_agents",
            })?
            .into_iter()
            .filter(|agent| !omitted.contains(agent))
            .collect::<Vec<_>>();
        if permitted_agents
            .iter()
            .any(|agent| !agent_ids.contains(agent))
        {
            return Err(TenantPackageError::ChannelAgentUnknown);
        }
        let allowed_groups = raw.allowed_groups.ok_or(TenantPackageError::ShapeInvalid {
            field: "channel.allowed_groups",
        })?;
        let audience = ChannelAudience::parse(&allowed_groups)
            .map_err(|error| TenantPackageError::AudienceInvalid { code: error.code() })?;
        channels.push(TenantChannel {
            id,
            name: required(raw.name, "channel.name")?,
            description: required(raw.description, "channel.description")?,
            permitted_agents,
            allowed_groups,
            audience,
        });
    }

    let RawModel {
        provider,
        credential_secret_ref,
        default_model,
        pricing,
    } = model_file.model;
    if provider != "openai" {
        return Err(TenantPackageError::ModelProviderUnsupported);
    }
    let default_model = required(default_model, "model.default_model")?;
    let rate_card = pricing
        .map(|pricing| {
            let observed_at =
                OffsetDateTime::parse(&pricing.observed_at, &Rfc3339).map_err(|_| {
                    TenantPackageError::ShapeInvalid {
                        field: "model.pricing.observed_at",
                    }
                })?;
            ProviderRateCard::new(ProviderRateCardInput {
                family: ProviderBillingFamily::OpenAiCompatible,
                model: default_model.clone(),
                currency: pricing.currency,
                max_input_micro_units_per_million_tokens: pricing
                    .max_input_micro_units_per_million_tokens,
                max_output_micro_units_per_million_tokens: pricing
                    .max_output_micro_units_per_million_tokens,
                source_url: pricing.source_url,
                source_sha256: pricing.source_sha256,
                observed_at,
            })
            .map_err(|_| TenantPackageError::ShapeInvalid {
                field: "model.pricing",
            })
        })
        .transpose()?;
    let model = TenantModel {
        provider,
        credential_secret_ref: required(credential_secret_ref, "model.credential_secret_ref")?,
        default_model,
        rate_card,
    };
    let mut knowledge_sources = Vec::new();
    for source in knowledge_file.sources {
        if !["google-drive", "microsoft-onedrive"].contains(&source.source_type.as_str()) {
            return Err(TenantPackageError::KnowledgeSourceUnsupported);
        }
        knowledge_sources.push(TenantKnowledgeSource {
            source_type: source.source_type,
            roots: source.roots.ok_or(TenantPackageError::ShapeInvalid {
                field: "knowledge.source.roots",
            })?,
        });
    }

    Ok(TenantPackage {
        tenant_id,
        product_name,
        theme_status,
        agents,
        channels,
        model,
        knowledge_sources,
    })
}

fn managed_standing_prompt(name: &str, title: &str, role_description: &str) -> String {
    format!(
        "You are {name}, {title}.\n\n{role_description}\n\n\
         This standing role applies in every channel. Treat channel messages as task-specific instructions within it."
    )
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(
    value: &str,
    file: TenantPackageFile,
) -> Result<T, TenantPackageError> {
    serde_yaml::from_str(value).map_err(|_| TenantPackageError::YamlInvalid { file })
}

fn required(value: Option<String>, field: &'static str) -> Result<String, TenantPackageError> {
    value
        .filter(|value| !trim_ecmascript(value).is_empty())
        .ok_or(TenantPackageError::RequiredString { field })
}

fn validate_public_brand(tenant_id: &str, product_name: &str) -> Result<(), TenantPackageError> {
    let tenant = tenant_id.to_ascii_lowercase();
    let product = product_name.to_ascii_lowercase();
    if ["openbot", "copilotkit", "codex", "openai", "grok", "xai"]
        .iter()
        .any(|mark| tenant.contains(mark) || product.contains(mark))
    {
        Err(TenantPackageError::BrandRestricted)
    } else {
        Ok(())
    }
}

/// 已完成文件读取、展开与 checksum 的 package；Debug 不打印本机路径。
#[derive(Clone, PartialEq, Eq)]
pub struct LoadedTenantPackage {
    /// 校验后的 package。
    pub package: TenantPackage,
    /// 管理员配置的来源路径。
    pub source_path: String,
    /// 五份展开后 YAML 的 lowercase SHA-256。
    pub checksum: String,
}

impl LoadedTenantPackage {
    /// 校验 source/checksum 元数据并构造。
    ///
    /// # Errors
    ///
    /// 空 source path 或非 64 位 lowercase hex checksum 被拒绝。
    pub fn new(
        package: TenantPackage,
        source_path: String,
        checksum: String,
    ) -> Result<Self, TenantPackageError> {
        if source_path.is_empty()
            || checksum.len() != 64
            || !checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TenantPackageError::LoadedMetadataInvalid);
        }
        Ok(Self {
            package,
            source_path,
            checksum,
        })
    }
}

impl core::fmt::Debug for LoadedTenantPackage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LoadedTenantPackage")
            .field("tenant_id", &self.package.tenant_id)
            .field("source_path", &"<configured>")
            .field("checksum", &self.checksum)
            .finish_non_exhaustive()
    }
}

/// 浏览器可见的 build/startup 配置；只有 brand，不含 provider、路径、theme 或 secret。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationConfiguration {
    /// Brand。
    pub brand: ApplicationBrand,
}

/// 浏览器可见 brand。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationBrand {
    /// Tenant id。
    pub tenant_id: String,
    /// 产品名。
    pub product_name: String,
}

/// 只投影 browser 可以安全知道的 brand。
#[must_use]
pub fn create_application_configuration(package: &TenantPackage) -> ApplicationConfiguration {
    ApplicationConfiguration {
        brand: ApplicationBrand {
            tenant_id: package.tenant_id.clone(),
            product_name: package.product_name.clone(),
        },
    }
}

/// 包同步时的部署身份/IdP group mapping 上下文。
#[derive(Clone, Debug)]
pub enum TenantPackageAudienceContext {
    /// 单用户：唯一 principal 进入全部包 channel。
    SingleUser {
        /// 唯一 principal。
        principal: ActorId,
    },
    /// 多用户：providers 与其中有 mapping 的子集分开传递。
    MultiUser {
        /// 已配置 provider，稳定排序去重。
        providers: Vec<IdentityProviderId>,
        /// 有明确 claim path/normalization 的 mappings。
        mappings: Vec<IdpGroupMapping>,
    },
}

impl TenantPackageAudienceContext {
    /// 构造单用户上下文。
    ///
    /// # Errors
    ///
    /// principal 为空时拒绝。
    pub fn single_user(principal: ActorId) -> Result<Self, TenantPackageError> {
        if principal.as_str().is_empty() {
            return Err(TenantPackageError::AudienceContextInvalid);
        }
        Ok(Self::SingleUser { principal })
    }

    /// 构造多用户上下文，要求每条 mapping 的 provider 都存在于 providers。
    ///
    /// # Errors
    ///
    /// mapping 指向未配置 provider 时拒绝。
    pub fn multi_user(
        providers: impl IntoIterator<Item = IdentityProviderId>,
        mappings: Vec<IdpGroupMapping>,
    ) -> Result<Self, TenantPackageError> {
        let mut providers: Vec<_> = providers.into_iter().collect();
        providers.sort_unstable();
        providers.dedup();
        if mappings
            .iter()
            .any(|mapping| !providers.contains(mapping.provider()))
        {
            return Err(TenantPackageError::AudienceContextInvalid);
        }
        Ok(Self::MultiUser {
            providers,
            mappings,
        })
    }

    /// 部署模式。
    #[must_use]
    pub const fn mode(&self) -> DeploymentMode {
        match self {
            Self::SingleUser { .. } => DeploymentMode::SingleUser,
            Self::MultiUser { .. } => DeploymentMode::MultiUser,
        }
    }

    /// 单用户 principal；多用户为 `None`。
    #[must_use]
    pub const fn single_user_principal(&self) -> Option<&ActorId> {
        match self {
            Self::SingleUser { principal } => Some(principal),
            Self::MultiUser { .. } => None,
        }
    }

    fn providers(&self) -> &[IdentityProviderId] {
        match self {
            Self::SingleUser { .. } => &[],
            Self::MultiUser { providers, .. } => providers,
        }
    }

    fn mappings(&self) -> &[IdpGroupMapping] {
        match self {
            Self::SingleUser { .. } => &[],
            Self::MultiUser { mappings, .. } => mappings,
        }
    }
}

/// 一个 channel 的 audience 校验报告。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantChannelAudienceReport {
    /// Channel id。
    pub channel_id: ChannelId,
    /// 组是否参与裁决。
    pub note: AudienceNote,
    /// 已配置但没有 mapping 的 provider。
    pub providers_without_mapping: Vec<IdentityProviderId>,
}

/// 对 package 所有 channel 运行 §6.5 部署级 audience 校验。
///
/// # Errors
///
/// 多用户具名组没有任何可用 mapping 时返回领域稳定错误，并保留缺 mapping 的 provider 清单。
pub fn validate_package_audiences(
    package: &TenantPackage,
    context: &TenantPackageAudienceContext,
) -> Result<Vec<TenantChannelAudienceReport>, AudienceValidationError> {
    package
        .channels
        .iter()
        .map(|channel| {
            let report = validate_audience(
                &channel.audience,
                context.mode(),
                context.providers(),
                context.mappings(),
            )?;
            Ok(TenantChannelAudienceReport {
                channel_id: ChannelId::new(&channel.id),
                note: report.note(),
                providers_without_mapping: report.providers_without_mapping().to_vec(),
            })
        })
        .collect()
}

/// PostgreSQL 同步冲突类别。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TenantPackageCollision {
    /// 数据库已有 deployment route 保留名 Agent。
    ReservedAgent,
    /// Package Agent id 撞到用户创建的 canonical Agent。
    UserAgent,
    /// Package Agent id 撞到用户拥有的 profile。
    UserProfile,
    /// Agent 已属于另一个 package。
    OtherPackageAgent,
    /// Channel id 撞到用户创建或另一个 package 的 channel。
    Channel,
}

/// Tenant Package 持久化 port 失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantPackageStoreError {
    /// PostgreSQL 当前不可用。
    #[error("tenant_package_store_unavailable")]
    Unavailable,
    /// 行/schema 与封闭类型不一致。
    #[error("tenant_package_store_corrupt field={field}")]
    Corrupt {
        /// 静态字段名。
        field: &'static str,
    },
    /// 所有权/保留名冲突。
    #[error("tenant_package_store_collision kind={kind:?}")]
    Collision {
        /// 冲突类别。
        kind: TenantPackageCollision,
    },
}

/// 同步完成后的机械计数与显式兼容状态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantPackageSyncReport {
    /// Tenant id。
    pub tenant_id: String,
    /// 同步 Agent 数。
    pub agents: u64,
    /// 同步 Channel 数。
    pub channels: u64,
    /// 新增 membership 数。
    pub memberships_granted: u64,
    /// 删除 membership 数。
    pub memberships_revoked: u64,
    /// 因 membership 撤销而推进 auth generation 的用户数。
    pub generations_advanced: u64,
    /// 是否按单用户规则忽略 group 并 provision 全部 channel。
    pub single_user_groups_ignored: bool,
    /// 仅兼容解析、未执行本地索引的 knowledge source 数。
    pub knowledge_sources_compatibility_only: u64,
    /// 是否识别并忽略了旧 runtime theme 声明。
    pub runtime_theme_ignored: bool,
}

/// Application 定义的 package 同步 port；infra 实现 PostgreSQL 事务。
#[async_trait]
pub trait TenantPackageSynchronizer: Send + Sync {
    /// 同步已校验 package 与 audience 投影。
    async fn synchronize(
        &self,
        package: &LoadedTenantPackage,
        context: &TenantPackageAudienceContext,
        audiences: &[TenantChannelAudienceReport],
    ) -> Result<TenantPackageSyncReport, TenantPackageStoreError>;
}

/// 部署级 audience 或持久化失败。
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantPackageApplyError {
    /// 具名组缺 IdP/mapping。
    #[error(transparent)]
    Audience(#[from] AudienceValidationError),
    /// PostgreSQL 同步失败。
    #[error(transparent)]
    Store(#[from] TenantPackageStoreError),
}

/// 先运行第一真源 audience 校验，再调用唯一同步 port。
///
/// # Errors
///
/// audience 或持久化任一失败时不返回成功报告。
pub async fn synchronize_tenant_package<S: TenantPackageSynchronizer + ?Sized>(
    synchronizer: &S,
    package: &LoadedTenantPackage,
    context: &TenantPackageAudienceContext,
) -> Result<TenantPackageSyncReport, TenantPackageApplyError> {
    let audiences = validate_package_audiences(&package.package, context)?;
    synchronizer
        .synchronize(package, context, &audiences)
        .await
        .map_err(Into::into)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBrand {
    tenant: RawTenant,
    #[serde(default)]
    skin: Option<RawSkin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTenant {
    id: String,
    product_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkin {
    stylesheet: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgents {
    agents: Vec<RawAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    role_description: Option<String>,
    #[serde(default)]
    avatar_seed: Option<String>,
    #[serde(rename = "type", default)]
    agent_type: Option<String>,
    #[serde(default)]
    system_prompt: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(rename = "providerSource", default)]
    provider_source: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannels {
    channels: Vec<RawChannel>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChannel {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    permitted_agents: Option<Vec<String>>,
    #[serde(default)]
    allowed_groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModelFile {
    model: RawModel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModel {
    provider: String,
    #[serde(default)]
    credential_secret_ref: Option<String>,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default)]
    pricing: Option<RawPricing>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPricing {
    currency: String,
    max_input_micro_units_per_million_tokens: u64,
    max_output_micro_units_per_million_tokens: u64,
    source_url: String,
    source_sha256: String,
    observed_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKnowledge {
    sources: Vec<RawKnowledgeSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKnowledgeSource {
    #[serde(rename = "type")]
    source_type: String,
    #[serde(default)]
    roots: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbot_domain::identity::groups::{GroupClaimPath, GroupNormalization, IdpGroupMapping};

    fn valid_files() -> TenantPackageFiles {
        TenantPackageFiles {
            brand: "tenant: { id: fintech, product_name: Ledgerline }".to_owned(),
            agents: "agents: [{ id: knowledge, name: Knowledge, title: Company Knowledge, role_description: Answer company questions., avatar_seed: knowledge, type: built-in, system_prompt: Answer from knowledge. }]".to_owned(),
            channels: "channels: [{ id: company, name: Company, description: Knowledge channel, permitted_agents: [knowledge], allowed_groups: [all] }]".to_owned(),
            model: "model: { provider: openai, credential_secret_ref: openai-key, default_model: gpt-4.1 }".to_owned(),
            knowledge: "sources: []".to_owned(),
        }
    }

    #[test]
    fn model_pricing_is_optional_but_when_present_is_an_exact_attested_snapshot() {
        let mut files = valid_files();
        files.model = format!(
            "model:\n  provider: openai\n  credential_secret_ref: openai-key\n  default_model: gpt-4.1\n  pricing:\n    currency: USD\n    max_input_micro_units_per_million_tokens: 1500000\n    max_output_micro_units_per_million_tokens: 2000000\n    source_url: https://prices.example.test/archive/2026-08-30\n    source_sha256: {}\n    observed_at: 2026-08-30T12:00:00Z",
            "a".repeat(64)
        );
        let package = validate_tenant_package(files).unwrap();
        let rate = package.model.rate_card.expect("rate card");
        assert_eq!(rate.family(), ProviderBillingFamily::OpenAiCompatible);
        assert_eq!(rate.model(), "gpt-4.1");
        assert_eq!(rate.currency(), "USD");
        assert_eq!(rate.max_input_rate(), 1_500_000);
        assert_eq!(rate.max_output_rate(), 2_000_000);
        assert_eq!(rate.source_sha256(), "a".repeat(64));

        let mut invalid = valid_files();
        invalid.model = invalid.model.replace(
            "default_model: gpt-4.1",
            "default_model: gpt-4.1, pricing: { max_input_micro_units_per_million_tokens: 1 }",
        );
        assert_eq!(
            validate_tenant_package(invalid).unwrap_err(),
            TenantPackageError::YamlInvalid {
                file: TenantPackageFile::Model,
            },
        );
    }

    #[test]
    fn accepts_approved_variables_in_root_and_dark_blocks() {
        let mut files = valid_files();
        files.brand =
            "tenant: { id: fintech, product_name: Ledgerline }\nskin: { stylesheet: theme.css }"
                .to_owned();
        let package = validate_tenant_package(files).unwrap();
        assert_eq!(
            package.theme_status,
            TenantThemeStatus::CompatibilityInputIgnored
        );
        let tokens = include_str!("../../../wrokbot-ui/design/tokens.toml");
        assert!(tokens.contains("light_selector = \":root\""));
        assert!(tokens.contains("dark_selector = \".dark\""));
        assert!(tokens.contains("system_dark_selector = \":root:not(.light)\""));
    }

    #[test]
    fn rejects_imports_selectors_and_unsupported_variables() {
        assert_eq!(
            TENANT_PACKAGE_FILENAMES,
            [
                "brand.yaml",
                "agents.yaml",
                "channels.yaml",
                "model.yaml",
                "knowledge.yaml"
            ]
        );
        assert!(!TENANT_PACKAGE_FILENAMES.contains(&"theme.css"));
        assert!(!core::any::type_name::<TenantPackageFiles>().contains("Theme"));
        let mut files = valid_files();
        files.brand = "tenant: { id: openbot, product_name: OpenBot }".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap_err(),
            TenantPackageError::BrandRestricted
        );
    }

    #[test]
    fn rejects_an_agent_without_a_title() {
        let mut files = valid_files();
        files.agents = "agents: [{ id: knowledge, name: Knowledge, role_description: Answer., type: built-in, system_prompt: Answer. }]".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap_err().code(),
            "tenant_package_required_string"
        );
    }

    #[test]
    fn rejects_an_agent_without_a_role_description() {
        let mut files = valid_files();
        files.agents = "agents: [{ id: knowledge, name: Knowledge, title: Knowledge, type: built-in, system_prompt: Answer. }]".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap_err().code(),
            "tenant_package_required_string"
        );
    }

    #[test]
    fn rejects_an_agent_whose_id_is_the_deployment_route() {
        for reserved in ["policy", "fleet"] {
            let mut files = valid_files();
            files.agents = format!(
                "agents: [{{ id: {reserved}, name: Reserved, title: Reserved, role_description: Reserved., type: built-in, system_prompt: Reserved. }}]"
            );
            assert_eq!(
                validate_tenant_package(files).unwrap_err(),
                TenantPackageError::AgentIdReserved
            );
        }
    }

    #[test]
    fn an_id_that_merely_contains_a_reserved_name_is_fine() {
        let mut files = valid_files();
        files.agents = "agents: [{ id: policy-desk, name: Policy Desk, title: Policy, role_description: Answer., type: built-in, system_prompt: Answer. }]".to_owned();
        files.channels = "channels: [{ id: policy, name: Policy, description: Policy., permitted_agents: [policy-desk], allowed_groups: [all] }]".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap().agents[0].id,
            "policy-desk"
        );
    }

    #[test]
    fn parses_an_explicit_avatar_seed_and_leaves_an_omitted_seed_undefined() {
        let mut files = valid_files();
        files.agents = "agents:\n  - { id: knowledge, name: Knowledge, title: Knowledge, role_description: Answer., avatar_seed: seed, type: built-in, system_prompt: Answer. }\n  - { id: risk, name: Risk, title: Risk, role_description: Investigate., type: remote-ag-ui, endpoint: https://risk.example/ag-ui }".to_owned();
        files.channels = "channels: [{ id: company, name: Company, description: Test., permitted_agents: [knowledge, risk], allowed_groups: [all] }]".to_owned();
        let package = validate_tenant_package(files).unwrap();
        assert_eq!(package.agents[0].avatar_seed.as_deref(), Some("seed"));
        assert_eq!(package.agents[1].avatar_seed, None);
    }

    #[test]
    fn rejects_an_empty_optional_avatar_seed() {
        let mut files = valid_files();
        files.agents = "agents: [{ id: knowledge, name: Knowledge, title: Knowledge, role_description: Answer., avatar_seed: '', type: built-in, system_prompt: Answer. }]".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap_err().code(),
            "tenant_package_required_string"
        );
    }

    #[test]
    fn creates_a_browser_safe_application_configuration() {
        let package = validate_tenant_package(valid_files()).unwrap();
        assert_eq!(
            create_application_configuration(&package),
            ApplicationConfiguration {
                brand: ApplicationBrand {
                    tenant_id: "fintech".to_owned(),
                    product_name: "Ledgerline".to_owned(),
                }
            }
        );
    }

    #[test]
    fn accepts_the_complete_fintech_package_and_normalizes_agent_types() {
        let mut files = valid_files();
        files.brand =
            "tenant:\n  id: fintech\n  product_name: Ledgerline\nskin:\n  stylesheet: theme.css"
                .to_owned();
        files.agents = "agents:\n  - { id: knowledge, name: Knowledge, title: Knowledge, role_description: Answer., type: built-in, system_prompt: Answer. }\n  - { id: risk, name: Risk, title: Risk, role_description: Investigate., type: remote-ag-ui, endpoint: https://risk.example/ag-ui }".to_owned();
        files.channels = "channels: [{ id: company, name: Company, description: Test., permitted_agents: [knowledge, risk], allowed_groups: [all, risk] }]".to_owned();
        files.knowledge = "sources: [{ type: google-drive, roots: [Policies] }]".to_owned();
        let package = validate_tenant_package(files).unwrap();
        assert_eq!(package.agents[0].agent_type.as_str(), "built_in");
        assert_eq!(package.agents[1].agent_type.as_str(), "remote_ag_ui");
        assert_eq!(package.knowledge_sources.len(), 1);
        assert_eq!(
            validate_package_audiences(
                &package,
                &TenantPackageAudienceContext::single_user(ActorId::new("dev-local-user")).unwrap()
            )
            .unwrap()[0]
                .note,
            AudienceNote::SingleUserGroupsIgnored
        );
        let no_mapping = TenantPackageAudienceContext::multi_user([], Vec::new()).unwrap();
        assert_eq!(
            validate_package_audiences(&package, &no_mapping)
                .unwrap_err()
                .code(),
            "channel_named_groups_without_identity_provider"
        );
        let provider = IdentityProviderId::new("directory");
        let mapping = IdpGroupMapping::new(
            provider.clone(),
            GroupClaimPath::from_dotted("groups").unwrap(),
            GroupNormalization::TrimLowercase,
        );
        let mapped = TenantPackageAudienceContext::multi_user([provider], vec![mapping]).unwrap();
        assert!(validate_package_audiences(&package, &mapped).is_ok());
    }

    #[test]
    fn rejects_a_channel_that_refers_to_an_unknown_agent() {
        let mut files = valid_files();
        files.channels = "channels: [{ id: company, name: Company, description: Test., permitted_agents: [missing], allowed_groups: [all] }]".to_owned();
        assert_eq!(
            validate_tenant_package(files).unwrap_err(),
            TenantPackageError::ChannelAgentUnknown
        );
    }

    #[test]
    fn omits_a_remote_coworker_whose_endpoint_expanded_to_nothing() {
        let mut files = valid_files();
        files.agents = "agents:\n  - { id: knowledge, name: Knowledge, title: Knowledge, role_description: Answer., type: built-in, system_prompt: Answer. }\n  - { id: risk, name: Risk, type: remote-ag-ui, endpoint: '' }".to_owned();
        files.channels = "channels: [{ id: company, name: Company, description: Test., permitted_agents: [knowledge, risk], allowed_groups: [all] }]".to_owned();
        let package = validate_tenant_package(files).unwrap();
        assert_eq!(package.agents.len(), 1);
        assert_eq!(package.channels[0].permitted_agents, ["knowledge"]);
    }

    #[test]
    fn managed_endpoint_sentinel_becomes_the_in_process_managed_provider_slot() {
        let mut files = valid_files();
        files.agents = format!(
            "agents:\n  - {{ id: risk, name: Risk, title: Compliance, role_description: Investigate controls., type: remote-ag-ui, endpoint: {MANAGED_AGENT_IN_PROCESS_ENDPOINT} }}"
        );
        files.channels = "channels: [{ id: risk, name: Risk, description: Test., permitted_agents: [risk], allowed_groups: [all] }]".to_owned();
        let package = validate_tenant_package(files).unwrap();
        assert_eq!(package.agents[0].agent_type, TenantAgentType::BuiltIn);
        assert!(matches!(
            &package.agents[0].configuration,
            TenantAgentConfiguration::BuiltIn {
                system_prompt,
                provider_source: BuiltInProviderSource::Managed,
            } if system_prompt.starts_with("You are Risk, Compliance.")
        ));
    }

    fn agents_with_provider_source(value: &str) -> TenantPackageFiles {
        let mut files = valid_files();
        files.agents = format!(
            "agents:\n  - id: knowledge\n    name: Knowledge\n    title: Knowledge\n    role_description: Answer.\n    type: built-in\n    system_prompt: Answer.\n    providerSource: {value}\n"
        );
        files
    }

    #[test]
    fn built_in_provider_source_parses_extension_key() {
        let package =
            validate_tenant_package(agents_with_provider_source("extension:crabcode")).unwrap();
        assert_eq!(package.agents[0].agent_type, TenantAgentType::BuiltIn);
        assert_eq!(
            package.agents[0].configuration,
            TenantAgentConfiguration::BuiltIn {
                system_prompt: "Answer.".to_owned(),
                provider_source: BuiltInProviderSource::Extension(
                    ProviderExtensionKey::new("crabcode").unwrap()
                ),
            }
        );
    }

    #[test]
    fn built_in_provider_source_rejects_malformed_extension_key() {
        for value in [
            "'extension:'".to_owned(),
            "extension:Crab".to_owned(),
            format!("extension:{}", "a".repeat(33)),
        ] {
            let error = validate_tenant_package(agents_with_provider_source(&value)).unwrap_err();
            assert_eq!(
                error,
                TenantPackageError::ShapeInvalid {
                    field: "agent.providerSource"
                },
                "{value}"
            );
            assert!(error.to_string().contains("providerSource"), "{value}");
        }
    }

    #[test]
    fn built_in_provider_source_extension_round_trips_as_text() {
        let package =
            validate_tenant_package(agents_with_provider_source("extension:crab_code-1")).unwrap();
        let TenantAgentConfiguration::BuiltIn {
            provider_source, ..
        } = &package.agents[0].configuration
        else {
            panic!("built-in configuration");
        };
        let text = provider_source.as_str();
        assert_eq!(text, "extension:crab_code-1");
        assert_eq!(
            validate_tenant_package(agents_with_provider_source(&text))
                .unwrap()
                .agents[0]
                .configuration,
            package.agents[0].configuration
        );
        assert_eq!(BuiltInProviderSource::Package.as_str(), "package");
        assert_eq!(BuiltInProviderSource::Managed.as_str(), "managed");
    }

    fn environment(entries: &[(&str, &str)]) -> TenantPackageEnvironment {
        TenantPackageEnvironment::from_explicit(
            entries
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        )
    }

    #[test]
    fn takes_the_value_from_the_environment() {
        assert_eq!(
            expand_environment(
                "endpoint: ${AG_UI_URL}",
                TenantPackageFile::Agents,
                &environment(&[("AG_UI_URL", "https://bots.example/ag-ui")])
            )
            .unwrap(),
            "endpoint: https://bots.example/ag-ui"
        );
    }

    #[test]
    fn falls_back_to_the_default_when_the_name_is_not_set() {
        assert_eq!(
            expand_environment(
                "endpoint: ${AG_UI_URL:-http://localhost:4200}",
                TenantPackageFile::Agents,
                &TenantPackageEnvironment::default()
            )
            .unwrap(),
            "endpoint: http://localhost:4200"
        );
    }

    #[test]
    fn prefers_the_environment_over_the_default() {
        assert_eq!(
            expand_environment(
                "endpoint: ${AG_UI_URL:-http://localhost:4200}",
                TenantPackageFile::Agents,
                &environment(&[("AG_UI_URL", "https://bots.example")])
            )
            .unwrap(),
            "endpoint: https://bots.example"
        );
    }

    #[test]
    fn treats_an_empty_value_as_unset() {
        assert_eq!(
            expand_environment(
                "endpoint: ${AG_UI_URL:-http://localhost:4200}",
                TenantPackageFile::Agents,
                &environment(&[("AG_UI_URL", "")])
            )
            .unwrap(),
            "endpoint: http://localhost:4200"
        );
    }

    #[test]
    fn an_empty_default_is_allowed_and_is_not_an_error() {
        assert_eq!(
            expand_environment(
                "suffix: ${NOTHING:-}",
                TenantPackageFile::Agents,
                &TenantPackageEnvironment::default()
            )
            .unwrap(),
            "suffix: "
        );
    }

    #[test]
    fn refuses_a_name_with_neither_a_value_nor_a_default() {
        let error = expand_environment(
            "endpoint: ${AG_UI_URL}",
            TenantPackageFile::Agents,
            &TenantPackageEnvironment::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), "tenant_package_environment_missing");
        assert!(!error.to_string().contains("endpoint:"));
    }
}
