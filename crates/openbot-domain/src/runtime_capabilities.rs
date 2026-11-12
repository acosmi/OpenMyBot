//! 认证后产品能力的纯领域投影（§15.5 / R238 / PA-08）。
//!
//! # 范围
//!
//! 本模块把调用方提供的**内部事实快照**组合成固定 13 项能力的五态结果。它不读时钟、
//! 随机数、OS、数据库、UA、页面名、`isTauri` 或编译 feature，也不签发 capability / 票据 /
//! 授权材料。真实 `GetRuntimeCapabilities`、HTTP/IPC DTO 与双宿主接线仍由后续 owner 完成。
//!
//! 输入类型名称停在「声明 / 观察」：[`BindingClaim`] 不是已证明授权，构造入口也不叫
//! verified / authorized。生产者仍须在接线时核验 actor、session、窗口与 OS/Provider 观察。
//!
//! # 组合规则
//!
//! 五态定义本身带前提：`unsupported` 只描述平台/构建未实现；`unconfigured` /
//! `permission_required` / `unavailable` / `ready` 都以「已支持」为前提。实现缺失或独立
//! API 缺失时，其余观察不适用。
//!
//! 已支持之后，本核收集所有适用阻断项。**同一能力若同时落入两种以上阻断五态**，第一真源
//! 未规定显示优先级，本核返回 [`ProjectionFault::UnresolvedBlockers`]，不丢掉阻断项去
//! 返回 `ready`，也不另发一套产品优先级。可判定输入正常投影。
//!
//! `hostMode` 只进入输出与窗口形态校验；宿主模式本身不能使任何控制能力变为 `ready`。
//!
//! # 本批明确不做
//!
//! - Serde 对外 DTO、HTTP 路由、全局缓存。
//! - 兑换、执行、授权、越过 action-time 校验的 API。
//! - 关闭 V5-CAP-01 的真实双宿主、认证/no-store、窗口生命周期与前端旅程。

use core::fmt;
use core::num::NonZeroU64;

use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::ids::ActorId;

use crate::identity::generation::{GenerationMismatch, check as check_generation};

/// 投影 schema；R426 对应公开 reply 的 `schemaVersion:1`。
pub const SCHEMA_VERSION: u8 = 1;

/// 投影 `revision` 最大字节数。
///
/// R426 公开协议最多64 ASCII字节。字符/长度校验不能识别秘密；生产者必须仅传本实际owner的非秘密世代标记。
pub const MAX_REVISION_BYTES: usize = 64;

/// 投影 `revision` 最小字节数。空串不能当 opaque 世代。
pub const MIN_REVISION_BYTES: usize = 1;

/// 窗口标签最大字节数。与既有 Desktop viewer 标签预算 256 对齐，不是新公开协议。
pub const MAX_WINDOW_LABEL_BYTES: usize = 256;

const ORDER: [CapabilityId; 13] = [
    CapabilityId::Workspace,
    CapabilityId::AgentTools,
    CapabilityId::ModelCustomV1,
    CapabilityId::ModelSelectionV2,
    CapabilityId::ModelSdkGateway,
    CapabilityId::ModelAccountBridge,
    CapabilityId::BrowserControl,
    CapabilityId::NativeControl,
    CapabilityId::PixelEgress,
    CapabilityId::LocalConfirmation,
    CapabilityId::BackupRestore,
    CapabilityId::DynamicSso,
    CapabilityId::DevicePairing,
];

/// 首批封闭能力 ID。未知 ID 不能在本模块构造成功状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityId {
    /// 只读工作台。
    Workspace,
    /// Agent 工具执行面。
    AgentTools,
    /// 自定义模型 v1 连接。
    ModelCustomV1,
    /// 模型选择 v2。
    ModelSelectionV2,
    /// SDK 网关来源。
    ModelSdkGateway,
    /// 账户桥来源。
    ModelAccountBridge,
    /// 浏览器控制。
    BrowserControl,
    /// 原生电脑控制。
    NativeControl,
    /// 像素出网。
    PixelEgress,
    /// 本机敏感写确认。
    LocalConfirmation,
    /// 备份恢复。
    BackupRestore,
    /// 动态 SSO。
    DynamicSso,
    /// 多设备配对。
    DevicePairing,
}

impl CapabilityId {
    /// 稳定字面量，与 §15.5 闭集逐字相同。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::AgentTools => "agent_tools",
            Self::ModelCustomV1 => "model_custom_v1",
            Self::ModelSelectionV2 => "model_selection_v2",
            Self::ModelSdkGateway => "model_sdk_gateway",
            Self::ModelAccountBridge => "model_account_bridge",
            Self::BrowserControl => "browser_control",
            Self::NativeControl => "native_control",
            Self::PixelEgress => "pixel_egress",
            Self::LocalConfirmation => "local_confirmation",
            Self::BackupRestore => "backup_restore",
            Self::DynamicSso => "dynamic_sso",
            Self::DevicePairing => "device_pairing",
        }
    }

    const fn ordinal(self) -> usize {
        match self {
            Self::Workspace => 0,
            Self::AgentTools => 1,
            Self::ModelCustomV1 => 2,
            Self::ModelSelectionV2 => 3,
            Self::ModelSdkGateway => 4,
            Self::ModelAccountBridge => 5,
            Self::BrowserControl => 6,
            Self::NativeControl => 7,
            Self::PixelEgress => 8,
            Self::LocalConfirmation => 9,
            Self::BackupRestore => 10,
            Self::DynamicSso => 11,
            Self::DevicePairing => 12,
        }
    }

    const fn is_acting(self) -> bool {
        matches!(
            self,
            Self::AgentTools | Self::BrowserControl | Self::NativeControl | Self::PixelEgress
        )
    }

    const fn uses_model_key(self) -> bool {
        matches!(
            self,
            Self::AgentTools
                | Self::ModelCustomV1
                | Self::ModelSelectionV2
                | Self::ModelSdkGateway
                | Self::ModelAccountBridge
                | Self::PixelEgress
        )
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 五态闭集。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityState {
    /// 平台/构建未实现。
    Unsupported,
    /// 已支持但缺合法配置。
    Unconfigured,
    /// 缺当前产品/OS 许可或明确确认。
    PermissionRequired,
    /// 当前检查可用。不授予永久 capability。
    Ready,
    /// 已支持但依赖故障、过期或尚不能证明。
    Unavailable,
}

impl CapabilityState {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Unconfigured => "unconfigured",
            Self::PermissionRequired => "permission_required",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
        }
    }
}

impl fmt::Display for CapabilityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 本地闭集理由。不接收远端 prose 或任意错误字符串。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReasonCode {
    /// 当前检查可用。
    CurrentChecksAvailable,
    /// 平台或构建未实现。
    PlatformUnimplemented,
    /// 缺独立 API。
    IndependentApiMissing,
    /// 实现或 API 尚不能证明。
    SupportUnproven,
    /// 缺必要发行依赖。
    ReleaseDependencyMissing,
    /// 发行依赖尚不能证明。
    ReleaseDependencyUnproven,
    /// 未配置 acting policy。
    PolicyUnconfigured,
    /// acting policy 为空。
    PolicyEmpty,
    /// acting policy 非法。
    PolicyInvalid,
    /// acting policy 尚不能证明。
    PolicyUnproven,
    /// 缺模型 key。
    ModelKeyMissing,
    /// 模型 key 尚不能证明。
    ModelKeyUnproven,
    /// 缺合法配置。
    ConfigurationMissing,
    /// 配置非法。
    ConfigurationInvalid,
    /// 配置尚不能证明。
    ConfigurationUnproven,
    /// 账户桥来源未同步，保持阻断。
    AccountBridgeSourceBlocked,
    /// 账户桥来源尚不能证明。
    AccountBridgeSourceUnproven,
    /// 缺当前产品许可。
    ProductPermissionRequired,
    /// 当前产品许可无法证明。
    ProductPermissionUnproven,
    /// 缺 OS 采集许可。
    OsPermissionCaptureRequired,
    /// 缺 OS 辅助功能许可。
    OsPermissionAccessibilityRequired,
    /// 缺 OS 输入许可。
    OsPermissionInputRequired,
    /// OS 许可尚不能证明。
    OsPermissionUnproven,
    /// OS 许可观察已过期。
    OsPermissionExpired,
    /// 需要本机确认。
    LocalConfirmationRequired,
    /// 本机确认仍在等待。
    LocalConfirmationPending,
    /// 本宿主不能进行系统确认。
    LocalConfirmationUnavailable,
    /// 本机确认尚不能证明。
    LocalConfirmationUnproven,
    /// 本机确认观察已过期。
    LocalConfirmationExpired,
    /// 缺像素出网同意。
    PixelConsentRequired,
    /// 像素同意尚不能证明。
    PixelConsentUnproven,
    /// 像素同意观察已过期。
    PixelConsentExpired,
    /// 缺 Computer source（含 NoScreenSession）。
    ComputerSourceMissing,
    /// 缺原生 source。
    NativeSourceMissing,
    /// 缺 screen source。
    ScreenSourceMissing,
    /// 来源尚不能证明。
    SourceUnproven,
    /// 来源观察已过期。
    SourceExpired,
    /// Provider 断开。
    ProviderDisconnected,
    /// Provider 尚不能证明。
    ProviderUnproven,
    /// Provider 观察已过期。
    ProviderExpired,
}

impl ReasonCode {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentChecksAvailable => "current_checks_available",
            Self::PlatformUnimplemented => "platform_unimplemented",
            Self::IndependentApiMissing => "independent_api_missing",
            Self::SupportUnproven => "support_unproven",
            Self::ReleaseDependencyMissing => "release_dependency_missing",
            Self::ReleaseDependencyUnproven => "release_dependency_unproven",
            Self::PolicyUnconfigured => "policy_unconfigured",
            Self::PolicyEmpty => "policy_empty",
            Self::PolicyInvalid => "policy_invalid",
            Self::PolicyUnproven => "policy_unproven",
            Self::ModelKeyMissing => "model_key_missing",
            Self::ModelKeyUnproven => "model_key_unproven",
            Self::ConfigurationMissing => "configuration_missing",
            Self::ConfigurationInvalid => "configuration_invalid",
            Self::ConfigurationUnproven => "configuration_unproven",
            Self::AccountBridgeSourceBlocked => "account_bridge_source_blocked",
            Self::AccountBridgeSourceUnproven => "account_bridge_source_unproven",
            Self::ProductPermissionRequired => "product_permission_required",
            Self::ProductPermissionUnproven => "product_permission_unproven",
            Self::OsPermissionCaptureRequired => "os_permission_capture_required",
            Self::OsPermissionAccessibilityRequired => "os_permission_accessibility_required",
            Self::OsPermissionInputRequired => "os_permission_input_required",
            Self::OsPermissionUnproven => "os_permission_unproven",
            Self::OsPermissionExpired => "os_permission_expired",
            Self::LocalConfirmationRequired => "local_confirmation_required",
            Self::LocalConfirmationPending => "local_confirmation_pending",
            Self::LocalConfirmationUnavailable => "local_confirmation_unavailable",
            Self::LocalConfirmationUnproven => "local_confirmation_unproven",
            Self::LocalConfirmationExpired => "local_confirmation_expired",
            Self::PixelConsentRequired => "pixel_consent_required",
            Self::PixelConsentUnproven => "pixel_consent_unproven",
            Self::PixelConsentExpired => "pixel_consent_expired",
            Self::ComputerSourceMissing => "computer_source_missing",
            Self::NativeSourceMissing => "native_source_missing",
            Self::ScreenSourceMissing => "screen_source_missing",
            Self::SourceUnproven => "source_unproven",
            Self::SourceExpired => "source_expired",
            Self::ProviderDisconnected => "provider_disconnected",
            Self::ProviderUnproven => "provider_unproven",
            Self::ProviderExpired => "provider_expired",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 远端 prose 不能进入理由闭集。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("runtime_capabilities_remote_prose_rejected")]
pub struct RemoteProseRejected;

/// 拒绝把任意远端错误字符串收进 [`ReasonCode`]。
#[must_use]
pub const fn reject_remote_prose(_text: &str) -> RemoteProseRejected {
    RemoteProseRejected
}

/// Rust 铸造的宿主模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostMode {
    /// 本机 Desktop。
    DesktopLocal,
    /// 远程 Desktop。
    DesktopRemote,
    /// Server。
    Server,
    /// 移动远程客户端。
    MobileRemote,
}

impl HostMode {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DesktopLocal => "desktop_local",
            Self::DesktopRemote => "desktop_remote",
            Self::Server => "server",
            Self::MobileRemote => "mobile_remote",
        }
    }

    const fn requires_window(self) -> bool {
        matches!(self, Self::DesktopLocal | Self::DesktopRemote)
    }
}

impl fmt::Display for HostMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 投影不授予业务动作。后续动作仍须 action-time 重验。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionAuthorization {
    /// 本投影明确未授予。
    NotGranted,
}

impl ActionAuthorization {
    /// 稳定字面量。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotGranted => "not_granted",
        }
    }
}

/// 会话是否仍可作为当前投影的绑定。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionLiveness {
    /// 仍视为当前会话。
    Active,
    /// 已退出。不得返回旧投影。
    Exited,
    /// 已撤权。不得返回旧投影。
    Revoked,
}

/// 实现是否存在。`Unknown` 不能当已实现。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Presence {
    /// 调用方未提供可证明观察。
    Unknown,
    /// 平台/构建未实现。
    Absent,
    /// 实现存在；独立 API 与发行依赖仍须单独证明。
    Present {
        /// 独立 API 是否存在。
        independent_api: Evidence,
        /// 必要发行依赖是否满足。
        release_dependency: Evidence,
    },
}

/// 三值证据。禁止 `unwrap_or(true)`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Evidence {
    /// 未知。
    Unknown,
    /// 明确缺失。
    Missing,
    /// 明确存在。
    Present,
}

/// acting policy 观察。空/坏/未配置不允许 acting。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PolicyFact {
    /// 未知。
    Unknown,
    /// 尚未保存合法 policy。
    Unconfigured,
    /// 已保存但两个规则集合都为空；显式合法deny-all仍Configured。
    Empty,
    /// 已保存但内容非法。
    Invalid,
    /// 已保存合法配置。deny-all 仍算已配置；具体动作仍走 action-time。
    Configured,
}

/// 模型 key 是否存在。缺 key 时工作台仍可投影，模型/工具不能 ready。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModelKeyFact {
    /// 未知。
    Unknown,
    /// 明确没有。
    Absent,
    /// 明确存在。本枚举不含密钥材料。
    Present,
}

/// 合法配置观察。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigFact {
    /// 未知。
    Unknown,
    /// 缺配置。
    Missing,
    /// 配置非法。
    Invalid,
    /// 合法配置存在。
    Present,
}

/// 账户桥固定来源是否可用。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BridgeSourceFact {
    /// 未知。
    Unknown,
    /// 用户未通知来源已同步，保持阻断。
    Blocked,
    /// 来源可进入后续核验。
    Available,
}

/// Provider 可证明性。不含远端错误正文。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProviderFact {
    /// 未知。
    Unknown,
    /// 观察已过期。
    Expired,
    /// 已断开。
    Disconnected,
    /// 当前可证明可达。
    Available,
}

/// Computer / native / screen 来源观察。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceFact {
    /// 未知。
    Unknown,
    /// 观察已过期。
    Expired,
    /// 明确没有（含 NoScreenSession）。
    Absent,
    /// 当前可证明存在。
    Present,
}

/// OS 或产品许可观察。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PermissionFact {
    /// 未知。
    Unknown,
    /// 观察已过期。
    Expired,
    /// 明确拒绝或未授予。
    Denied,
    /// 当前授予。
    Granted,
}

/// 本机确认观察。不是 fresh grant 本身。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LocalConfirmationFact {
    /// 未知。
    Unknown,
    /// 观察已过期。
    Expired,
    /// 本宿主不能确认。
    Unavailable,
    /// 需要确认。
    Required,
    /// 仍在等待。
    Pending,
    /// 当前窗口有未过期 grant。投影不复制 grant。
    Fresh,
}

/// 13 项实现观察。不从宿主模式推断。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImplementationSet {
    /// `workspace`。
    pub workspace: Presence,
    /// `agent_tools`。
    pub agent_tools: Presence,
    /// `model_custom_v1`。
    pub model_custom_v1: Presence,
    /// `model_selection_v2`。
    pub model_selection_v2: Presence,
    /// `model_sdk_gateway`。
    pub model_sdk_gateway: Presence,
    /// `model_account_bridge`。
    pub model_account_bridge: Presence,
    /// `browser_control`。
    pub browser_control: Presence,
    /// `native_control`。
    pub native_control: Presence,
    /// `pixel_egress`。
    pub pixel_egress: Presence,
    /// `local_confirmation`。
    pub local_confirmation: Presence,
    /// `backup_restore`。
    pub backup_restore: Presence,
    /// `dynamic_sso`。
    pub dynamic_sso: Presence,
    /// `device_pairing`。
    pub device_pairing: Presence,
}

impl ImplementationSet {
    fn for_id(self, id: CapabilityId) -> Presence {
        match id {
            CapabilityId::Workspace => self.workspace,
            CapabilityId::AgentTools => self.agent_tools,
            CapabilityId::ModelCustomV1 => self.model_custom_v1,
            CapabilityId::ModelSelectionV2 => self.model_selection_v2,
            CapabilityId::ModelSdkGateway => self.model_sdk_gateway,
            CapabilityId::ModelAccountBridge => self.model_account_bridge,
            CapabilityId::BrowserControl => self.browser_control,
            CapabilityId::NativeControl => self.native_control,
            CapabilityId::PixelEgress => self.pixel_egress,
            CapabilityId::LocalConfirmation => self.local_confirmation,
            CapabilityId::BackupRestore => self.backup_restore,
            CapabilityId::DynamicSso => self.dynamic_sso,
            CapabilityId::DevicePairing => self.device_pairing,
        }
    }
}

/// 某一模型来源自己的凭据存在性与 Provider 观察，不含秘密。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelSourceFacts {
    /// 此来源的凭据是否存在。
    pub key: ModelKeyFact,
    /// 此来源的 Provider 当前状态。
    pub provider: ProviderFact,
}

/// 调用方提供的内部事实快照。字段是观察，不是最终五态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilityFacts {
    /// 各能力实现。
    pub implementations: ImplementationSet,
    /// acting policy。
    pub acting_policy: PolicyFact,
    /// 模型 key 是否存在；不含密钥。
    pub model_key: ModelKeyFact,
    /// 自定义来源的独立观察。
    pub custom_model: ModelSourceFacts,
    /// SDK 来源的独立观察。
    pub sdk_model: ModelSourceFacts,
    /// 账户桥来源的独立观察。
    pub bridge_model: ModelSourceFacts,
    /// 自定义模型连接配置。
    pub custom_model_config: ConfigFact,
    /// 模型选择 v2 配置。
    pub selection_v2_config: ConfigFact,
    /// SDK 网关配置。
    pub sdk_gateway_config: ConfigFact,
    /// 账户桥配置。
    pub account_bridge_config: ConfigFact,
    /// 账户桥来源同步。
    pub account_bridge_source: BridgeSourceFact,
    /// 备份恢复配置。
    pub backup_config: ConfigFact,
    /// 动态 SSO 配置。
    pub sso_config: ConfigFact,
    /// 当前 SSO 协议来源；仅配置明确存在时消费。
    pub sso_provider: ProviderFact,
    /// 设备配对配置。
    pub pairing_config: ConfigFact,
    /// 模型 Provider。
    pub model_provider: ProviderFact,
    /// Computer / Engine source。
    pub computer_source: SourceFact,
    /// 原生 source。
    pub native_source: SourceFact,
    /// Screen source。
    pub screen_source: SourceFact,
    /// OS 采集许可。
    pub os_capture: PermissionFact,
    /// OS 辅助功能许可。
    pub os_accessibility: PermissionFact,
    /// OS 输入许可。
    pub os_input: PermissionFact,
    /// 向模型发送像素的同意。
    pub pixel_model_consent: PermissionFact,
    /// 当前主体对每项产品能力的许可；与 OS 许可独立。
    pub product_permissions: [PermissionFact; 13],
    /// 本机确认。
    pub local_confirmation: LocalConfirmationFact,
}

/// 当前或观察绑定的内部声明。不是已验证 `AuthContext`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingClaim {
    actor: ActorId,
    auth_generation: AuthGeneration,
    host_mode: HostMode,
    session: SessionLiveness,
    window: Option<WindowBindingClaim>,
}

impl BindingClaim {
    /// 声明一份绑定快照。名称不表示已证明授权。
    ///
    /// # Errors
    ///
    /// 窗口形态与宿主模式不符时返回 [`ProjectionFault::WindowShape`]。
    pub fn declare(
        actor: ActorId,
        auth_generation: AuthGeneration,
        host_mode: HostMode,
        session: SessionLiveness,
        window: Option<WindowBindingClaim>,
    ) -> Result<Self, ProjectionFault> {
        match (host_mode.requires_window(), window.is_some()) {
            (true, true) | (false, false) => Ok(Self {
                actor,
                auth_generation,
                host_mode,
                session,
                window,
            }),
            _ => Err(ProjectionFault::WindowShape),
        }
    }

    /// 声明中的 actor。
    #[must_use]
    pub fn actor(&self) -> &ActorId {
        &self.actor
    }

    /// 声明中的代际。
    #[must_use]
    pub const fn auth_generation(&self) -> AuthGeneration {
        self.auth_generation
    }

    /// 声明中的宿主模式。
    #[must_use]
    pub const fn host_mode(&self) -> HostMode {
        self.host_mode
    }

    /// 声明中的会话活性。
    #[must_use]
    pub const fn session(&self) -> SessionLiveness {
        self.session
    }

    /// 声明中的窗口绑定。
    #[must_use]
    pub const fn window(&self) -> Option<WindowBindingClaim> {
        self.window
    }
}

/// Desktop 窗口绑定声明。nonce 非零且不可复用的约束由生产者维持。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowBindingClaim {
    label: [u8; MAX_WINDOW_LABEL_BYTES],
    label_len: u16,
    nonce: NonZeroU64,
}

impl WindowBindingClaim {
    /// 声明窗口标签与非零 nonce。
    ///
    /// # Errors
    ///
    /// 标签为空、超长或含 NUL 时返回 [`ProjectionFault::WindowLabel`]；nonce 为 0 返回
    /// [`ProjectionFault::WindowNonce`]。
    pub fn declare(label: &str, nonce: u64) -> Result<Self, ProjectionFault> {
        let nonce = NonZeroU64::new(nonce).ok_or(ProjectionFault::WindowNonce)?;
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_WINDOW_LABEL_BYTES || bytes.contains(&0) {
            return Err(ProjectionFault::WindowLabel);
        }
        let mut stored = [0_u8; MAX_WINDOW_LABEL_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            label: stored,
            label_len: bytes.len() as u16,
            nonce,
        })
    }

    /// 标签原文。不进入投影输出。
    #[must_use]
    pub fn label(&self) -> &str {
        core::str::from_utf8(&self.label[..usize::from(self.label_len)]).unwrap_or("")
    }

    /// 非零窗口代次。
    #[must_use]
    pub const fn nonce(self) -> NonZeroU64 {
        self.nonce
    }
}

/// 有界 opaque 投影世代。不是 secret，也不授予权限。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectionRevision {
    bytes: [u8; MAX_REVISION_BYTES],
    len: u8,
}

impl ProjectionRevision {
    /// 校验并收下 opaque 字节。
    ///
    /// # Errors
    ///
    /// 空、超长或字符集越界时返回 [`RevisionFault`]。
    pub fn try_from_opaque(value: &str) -> Result<Self, RevisionFault> {
        let bytes = value.as_bytes();
        if bytes.len() < MIN_REVISION_BYTES {
            return Err(RevisionFault::Empty);
        }
        if bytes.len() > MAX_REVISION_BYTES {
            return Err(RevisionFault::TooLong);
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(RevisionFault::InvalidCharset);
        }
        let mut stored = [0_u8; MAX_REVISION_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: stored,
            len: bytes.len() as u8,
        })
    }

    /// opaque 原文。
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

impl fmt::Debug for ProjectionRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProjectionRevision")
            .field(&self.as_str())
            .finish()
    }
}

/// `revision` 边界失败。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RevisionFault {
    /// 空。
    #[error("runtime_capabilities_revision_empty")]
    Empty,
    /// 超过 [`MAX_REVISION_BYTES`]。
    #[error("runtime_capabilities_revision_too_long")]
    TooLong,
    /// 含非 `[A-Za-z0-9._-]` 字节。
    #[error("runtime_capabilities_revision_invalid_charset")]
    InvalidCharset,
}

impl RevisionFault {
    /// 稳定 code。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Empty => "runtime_capabilities_revision_empty",
            Self::TooLong => "runtime_capabilities_revision_too_long",
            Self::InvalidCharset => "runtime_capabilities_revision_invalid_charset",
        }
    }
}

/// 绑定对不上时的字段。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingField {
    /// actor。
    Actor,
    /// 宿主模式。
    Host,
}

/// 同一能力同时出现多种阻断五态，规范未规定优先级。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnresolvedBlockers {
    capability: CapabilityId,
    unconfigured: bool,
    permission_required: bool,
    unavailable: bool,
}

impl UnresolvedBlockers {
    /// 发生冲突的能力。
    #[must_use]
    pub const fn capability(self) -> CapabilityId {
        self.capability
    }

    /// 是否含 `unconfigured`。
    #[must_use]
    pub const fn unconfigured(self) -> bool {
        self.unconfigured
    }

    /// 是否含 `permission_required`。
    #[must_use]
    pub const fn permission_required(self) -> bool {
        self.permission_required
    }

    /// 是否含 `unavailable`。
    #[must_use]
    pub const fn unavailable(self) -> bool {
        self.unavailable
    }
}

/// 投影输入拒绝。可判定输入不走这条路。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProjectionFault {
    /// 当前绑定与观察绑定的身份字段不一致。
    #[error("runtime_capabilities_binding_mismatch")]
    BindingMismatch {
        /// 不一致的字段。
        field: BindingField,
    },
    /// 会话已退出。
    #[error("runtime_capabilities_session_exited")]
    SessionExited,
    /// 会话已撤权。
    #[error("runtime_capabilities_session_revoked")]
    SessionRevoked,
    /// 代际不是恰好相等。
    #[error("identity_generation_mismatch")]
    Generation(GenerationMismatch),
    /// 窗口已被替换。
    #[error("runtime_capabilities_window_replaced")]
    WindowReplaced,
    /// 窗口有无与宿主模式不符。
    #[error("runtime_capabilities_window_shape")]
    WindowShape,
    /// 窗口标签非法。
    #[error("runtime_capabilities_window_label")]
    WindowLabel,
    /// 窗口 nonce 为 0。
    #[error("runtime_capabilities_window_nonce")]
    WindowNonce,
    /// revision 越界。
    #[error("runtime_capabilities_revision")]
    Revision(RevisionFault),
    /// 多阻断态且规范未规定优先级。
    #[error("runtime_capabilities_unresolved_blockers")]
    UnresolvedBlockers(UnresolvedBlockers),
}

impl ProjectionFault {
    /// 稳定 code。
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BindingMismatch { .. } => "runtime_capabilities_binding_mismatch",
            Self::SessionExited => "runtime_capabilities_session_exited",
            Self::SessionRevoked => "runtime_capabilities_session_revoked",
            Self::Generation(GenerationMismatch::Stale) => "identity_generation_stale",
            Self::Generation(GenerationMismatch::FromTheFuture) => {
                "identity_generation_from_the_future"
            }
            Self::WindowReplaced => "runtime_capabilities_window_replaced",
            Self::WindowShape => "runtime_capabilities_window_shape",
            Self::WindowLabel => "runtime_capabilities_window_label",
            Self::WindowNonce => "runtime_capabilities_window_nonce",
            Self::Revision(fault) => fault.code(),
            Self::UnresolvedBlockers(_) => "runtime_capabilities_unresolved_blockers",
        }
    }
}

impl From<GenerationMismatch> for ProjectionFault {
    fn from(value: GenerationMismatch) -> Self {
        Self::Generation(value)
    }
}

impl From<RevisionFault> for ProjectionFault {
    fn from(value: RevisionFault) -> Self {
        Self::Revision(value)
    }
}

/// [`project_runtime_capabilities`] 的输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilityRequest<'a> {
    /// 当前宿主运行绑定；生产者在重启/切换连接时更新。
    pub current_runtime: NonZeroU64,
    /// 观察所属运行绑定，不可从页面传入。
    pub observed_runtime: NonZeroU64,
    /// 当前绑定声明。
    pub current_binding: &'a BindingClaim,
    /// 事实快照携带的观察绑定。
    pub observed_binding: &'a BindingClaim,
    /// 未核 revision 原文。
    pub revision: &'a str,
    /// 内部事实。
    pub facts: &'a RuntimeCapabilityFacts,
}

/// 单项能力状态。不含票据或 secret。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityStatus {
    id: CapabilityId,
    state: CapabilityState,
    reason_code: ReasonCode,
}

impl CapabilityStatus {
    /// 能力 ID。
    #[must_use]
    pub const fn id(self) -> CapabilityId {
        self.id
    }

    /// 五态。
    #[must_use]
    pub const fn state(self) -> CapabilityState {
        self.state
    }

    /// 闭集理由。
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        self.reason_code
    }
}

/// 当前投影。不是授权回执。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeCapabilityProjection {
    schema_version: u8,
    host_mode: HostMode,
    revision: ProjectionRevision,
    capabilities: [CapabilityStatus; 13],
    action_authorization: ActionAuthorization,
}

impl RuntimeCapabilityProjection {
    /// schema 版本。
    #[must_use]
    pub const fn schema_version(self) -> u8 {
        self.schema_version
    }

    /// 宿主模式。由绑定声明复制，不单独推断可用。
    #[must_use]
    pub const fn host_mode(self) -> HostMode {
        self.host_mode
    }

    /// opaque 世代。
    #[must_use]
    pub const fn revision(self) -> ProjectionRevision {
        self.revision
    }

    /// 固定 13 项，顺序确定、无重复。
    #[must_use]
    pub const fn capabilities(self) -> [CapabilityStatus; 13] {
        self.capabilities
    }

    /// 按 ID 取一项。
    #[must_use]
    pub const fn status(self, id: CapabilityId) -> CapabilityStatus {
        self.capabilities[id.ordinal()]
    }

    /// 投影不授予动作。恒为未授予。
    #[must_use]
    pub const fn action_authorization(self) -> ActionAuthorization {
        self.action_authorization
    }
}

/// 由内部事实组合出当前投影。
///
/// # Errors
///
/// 绑定不能核同、会话已退出/撤权、revision 非法，或已支持能力同时落入多种阻断五态。
pub fn project_runtime_capabilities(
    request: RuntimeCapabilityRequest<'_>,
) -> Result<RuntimeCapabilityProjection, ProjectionFault> {
    if request.current_runtime != request.observed_runtime {
        return Err(ProjectionFault::BindingMismatch {
            field: BindingField::Host,
        });
    }
    let host_mode = check_bindings(request.current_binding, request.observed_binding)?;
    let revision = ProjectionRevision::try_from_opaque(request.revision)?;
    let mut capabilities = [CapabilityStatus {
        id: CapabilityId::Workspace,
        state: CapabilityState::Unsupported,
        reason_code: ReasonCode::PlatformUnimplemented,
    }; 13];
    for (index, id) in ORDER.iter().copied().enumerate() {
        capabilities[index] = project_one(id, request.facts)?;
    }
    Ok(RuntimeCapabilityProjection {
        schema_version: SCHEMA_VERSION,
        host_mode,
        revision,
        capabilities,
        action_authorization: ActionAuthorization::NotGranted,
    })
}

fn check_bindings(
    current: &BindingClaim,
    observed: &BindingClaim,
) -> Result<HostMode, ProjectionFault> {
    if current.session == SessionLiveness::Revoked || observed.session == SessionLiveness::Revoked {
        return Err(ProjectionFault::SessionRevoked);
    }
    if current.session == SessionLiveness::Exited || observed.session == SessionLiveness::Exited {
        return Err(ProjectionFault::SessionExited);
    }
    if current.host_mode != observed.host_mode {
        return Err(ProjectionFault::BindingMismatch {
            field: BindingField::Host,
        });
    }
    if current.actor != observed.actor {
        return Err(ProjectionFault::BindingMismatch {
            field: BindingField::Actor,
        });
    }
    check_generation(observed.auth_generation, current.auth_generation)?;
    match (current.window, observed.window) {
        (None, None) => {}
        (Some(left), Some(right)) => {
            if left.nonce != right.nonce || left.label() != right.label() {
                return Err(ProjectionFault::WindowReplaced);
            }
        }
        _ => return Err(ProjectionFault::WindowShape),
    }
    Ok(current.host_mode)
}

#[derive(Clone, Copy)]
enum SupportGate {
    Unsupported(ReasonCode),
    Unproven(ReasonCode),
    Implemented { release_dependency: Evidence },
}

fn support_gate(presence: Presence) -> SupportGate {
    match presence {
        Presence::Absent => SupportGate::Unsupported(ReasonCode::PlatformUnimplemented),
        Presence::Unknown => SupportGate::Unproven(ReasonCode::SupportUnproven),
        Presence::Present {
            independent_api: Evidence::Missing,
            ..
        } => SupportGate::Unsupported(ReasonCode::IndependentApiMissing),
        Presence::Present {
            independent_api: Evidence::Unknown,
            ..
        } => SupportGate::Unproven(ReasonCode::SupportUnproven),
        Presence::Present {
            independent_api: Evidence::Present,
            release_dependency,
        } => SupportGate::Implemented { release_dependency },
    }
}

#[derive(Clone, Copy)]
struct Blocker {
    state: CapabilityState,
    reason: ReasonCode,
}

fn project_one(
    id: CapabilityId,
    facts: &RuntimeCapabilityFacts,
) -> Result<CapabilityStatus, ProjectionFault> {
    match support_gate(facts.implementations.for_id(id)) {
        SupportGate::Unsupported(reason) => Ok(status(id, CapabilityState::Unsupported, reason)),
        SupportGate::Unproven(reason) => Ok(status(id, CapabilityState::Unavailable, reason)),
        SupportGate::Implemented { release_dependency } => {
            let mut blockers = Vec::with_capacity(2);
            add_first_level_blockers(id, facts, release_dependency, &mut blockers);
            finish(id, &blockers)
        }
    }
}

/// Spec revision R487: after the support gate, blockers are evaluated in five fixed levels
/// (release dependency, product permission, configuration, source facts, OS permission and
/// on-the-spot consent). Only the first level with a blocker is collected, so `finish` sees
/// one level: same state reports the first collected reason, two states refuse the query.
fn add_first_level_blockers(
    id: CapabilityId,
    facts: &RuntimeCapabilityFacts,
    release_dependency: Evidence,
    blockers: &mut Vec<Blocker>,
) {
    push_release(blockers, release_dependency);
    if !blockers.is_empty() {
        return;
    }
    match facts.product_permissions[id.ordinal()] {
        PermissionFact::Granted => {}
        PermissionFact::Denied => blockers.push(perm(ReasonCode::ProductPermissionRequired)),
        PermissionFact::Unknown | PermissionFact::Expired => {
            blockers.push(unavail(ReasonCode::ProductPermissionUnproven))
        }
    }
    if !blockers.is_empty() {
        return;
    }
    if id.is_acting() {
        push_policy(blockers, facts.acting_policy);
    }
    let model = match id {
        CapabilityId::ModelCustomV1 => facts.custom_model,
        CapabilityId::ModelSdkGateway => facts.sdk_model,
        CapabilityId::ModelAccountBridge => facts.bridge_model,
        _ => ModelSourceFacts {
            key: facts.model_key,
            provider: facts.model_provider,
        },
    };
    if id.uses_model_key() {
        push_model_key(blockers, model.key);
    }
    match id {
        CapabilityId::ModelCustomV1 => push_config(blockers, facts.custom_model_config),
        CapabilityId::ModelSelectionV2 => push_config(blockers, facts.selection_v2_config),
        CapabilityId::ModelSdkGateway => push_config(blockers, facts.sdk_gateway_config),
        CapabilityId::ModelAccountBridge => push_config(blockers, facts.account_bridge_config),
        CapabilityId::BackupRestore => push_config(blockers, facts.backup_config),
        CapabilityId::DynamicSso => push_config(blockers, facts.sso_config),
        CapabilityId::DevicePairing => push_config(blockers, facts.pairing_config),
        CapabilityId::Workspace
        | CapabilityId::AgentTools
        | CapabilityId::BrowserControl
        | CapabilityId::NativeControl
        | CapabilityId::PixelEgress
        | CapabilityId::LocalConfirmation => {}
    }
    if !blockers.is_empty() {
        return;
    }
    // Reaching this level means every model key and configuration above is present.
    match id {
        CapabilityId::AgentTools
        | CapabilityId::ModelCustomV1
        | CapabilityId::ModelSelectionV2
        | CapabilityId::ModelSdkGateway => push_provider(blockers, model.provider),
        CapabilityId::ModelAccountBridge => {
            push_bridge_source(blockers, facts.account_bridge_source);
            if facts.account_bridge_source == BridgeSourceFact::Available {
                push_provider(blockers, model.provider);
            }
        }
        CapabilityId::BrowserControl => push_source(
            blockers,
            facts.computer_source,
            ReasonCode::ComputerSourceMissing,
        ),
        CapabilityId::NativeControl => push_source(
            blockers,
            facts.native_source,
            ReasonCode::NativeSourceMissing,
        ),
        CapabilityId::PixelEgress => {
            push_source(
                blockers,
                facts.screen_source,
                ReasonCode::ScreenSourceMissing,
            );
            push_provider(blockers, model.provider);
        }
        CapabilityId::DynamicSso => push_provider(blockers, facts.sso_provider),
        CapabilityId::Workspace
        | CapabilityId::LocalConfirmation
        | CapabilityId::BackupRestore
        | CapabilityId::DevicePairing => {}
    }
    if !blockers.is_empty() {
        return;
    }
    match id {
        CapabilityId::NativeControl => {
            push_os_permission(
                blockers,
                facts.os_accessibility,
                ReasonCode::OsPermissionAccessibilityRequired,
            );
            push_os_permission(
                blockers,
                facts.os_input,
                ReasonCode::OsPermissionInputRequired,
            );
        }
        CapabilityId::PixelEgress => {
            push_os_permission(
                blockers,
                facts.os_capture,
                ReasonCode::OsPermissionCaptureRequired,
            );
            push_pixel_consent(blockers, facts.pixel_model_consent);
        }
        CapabilityId::LocalConfirmation => {
            push_local_confirmation(blockers, facts.local_confirmation);
        }
        CapabilityId::Workspace
        | CapabilityId::AgentTools
        | CapabilityId::ModelCustomV1
        | CapabilityId::ModelSelectionV2
        | CapabilityId::ModelSdkGateway
        | CapabilityId::ModelAccountBridge
        | CapabilityId::BrowserControl
        | CapabilityId::BackupRestore
        | CapabilityId::DynamicSso
        | CapabilityId::DevicePairing => {}
    }
}

fn finish(id: CapabilityId, blockers: &[Blocker]) -> Result<CapabilityStatus, ProjectionFault> {
    if blockers.is_empty() {
        return Ok(status(
            id,
            CapabilityState::Ready,
            ReasonCode::CurrentChecksAvailable,
        ));
    }
    let mut unconfigured = false;
    let mut permission_required = false;
    let mut unavailable = false;
    for blocker in blockers {
        match blocker.state {
            CapabilityState::Unconfigured => unconfigured = true,
            CapabilityState::PermissionRequired => permission_required = true,
            CapabilityState::Unavailable => unavailable = true,
            CapabilityState::Unsupported | CapabilityState::Ready => {}
        }
    }
    let distinct = u8::from(unconfigured) + u8::from(permission_required) + u8::from(unavailable);
    if distinct >= 2 {
        return Err(ProjectionFault::UnresolvedBlockers(UnresolvedBlockers {
            capability: id,
            unconfigured,
            permission_required,
            unavailable,
        }));
    }
    Ok(status(id, blockers[0].state, blockers[0].reason))
}

fn status(id: CapabilityId, state: CapabilityState, reason_code: ReasonCode) -> CapabilityStatus {
    CapabilityStatus {
        id,
        state,
        reason_code,
    }
}

fn push_release(blockers: &mut Vec<Blocker>, evidence: Evidence) {
    match evidence {
        Evidence::Present => {}
        Evidence::Missing => blockers.push(unavail(ReasonCode::ReleaseDependencyMissing)),
        Evidence::Unknown => blockers.push(unavail(ReasonCode::ReleaseDependencyUnproven)),
    }
}

fn push_policy(blockers: &mut Vec<Blocker>, fact: PolicyFact) {
    match fact {
        PolicyFact::Configured => {}
        PolicyFact::Unconfigured => blockers.push(unconf(ReasonCode::PolicyUnconfigured)),
        PolicyFact::Empty => blockers.push(unconf(ReasonCode::PolicyEmpty)),
        PolicyFact::Invalid => blockers.push(unconf(ReasonCode::PolicyInvalid)),
        PolicyFact::Unknown => blockers.push(unavail(ReasonCode::PolicyUnproven)),
    }
}

fn push_model_key(blockers: &mut Vec<Blocker>, fact: ModelKeyFact) {
    match fact {
        ModelKeyFact::Present => {}
        ModelKeyFact::Absent => blockers.push(unconf(ReasonCode::ModelKeyMissing)),
        ModelKeyFact::Unknown => blockers.push(unavail(ReasonCode::ModelKeyUnproven)),
    }
}

fn push_config(blockers: &mut Vec<Blocker>, fact: ConfigFact) {
    match fact {
        ConfigFact::Present => {}
        ConfigFact::Missing => blockers.push(unconf(ReasonCode::ConfigurationMissing)),
        ConfigFact::Invalid => blockers.push(unconf(ReasonCode::ConfigurationInvalid)),
        ConfigFact::Unknown => blockers.push(unavail(ReasonCode::ConfigurationUnproven)),
    }
}

fn push_bridge_source(blockers: &mut Vec<Blocker>, fact: BridgeSourceFact) {
    match fact {
        BridgeSourceFact::Available => {}
        BridgeSourceFact::Blocked => blockers.push(unconf(ReasonCode::AccountBridgeSourceBlocked)),
        BridgeSourceFact::Unknown => {
            blockers.push(unavail(ReasonCode::AccountBridgeSourceUnproven))
        }
    }
}

fn push_provider(blockers: &mut Vec<Blocker>, fact: ProviderFact) {
    match fact {
        ProviderFact::Available => {}
        ProviderFact::Disconnected => blockers.push(unavail(ReasonCode::ProviderDisconnected)),
        ProviderFact::Unknown => blockers.push(unavail(ReasonCode::ProviderUnproven)),
        ProviderFact::Expired => blockers.push(unavail(ReasonCode::ProviderExpired)),
    }
}

fn push_source(blockers: &mut Vec<Blocker>, fact: SourceFact, missing: ReasonCode) {
    match fact {
        SourceFact::Present => {}
        SourceFact::Absent => blockers.push(unavail(missing)),
        SourceFact::Unknown => blockers.push(unavail(ReasonCode::SourceUnproven)),
        SourceFact::Expired => blockers.push(unavail(ReasonCode::SourceExpired)),
    }
}

fn push_os_permission(blockers: &mut Vec<Blocker>, fact: PermissionFact, denied: ReasonCode) {
    match fact {
        PermissionFact::Granted => {}
        PermissionFact::Denied => blockers.push(perm(denied)),
        PermissionFact::Unknown => blockers.push(unavail(ReasonCode::OsPermissionUnproven)),
        PermissionFact::Expired => blockers.push(unavail(ReasonCode::OsPermissionExpired)),
    }
}

fn push_pixel_consent(blockers: &mut Vec<Blocker>, fact: PermissionFact) {
    match fact {
        PermissionFact::Granted => {}
        PermissionFact::Denied => blockers.push(perm(ReasonCode::PixelConsentRequired)),
        PermissionFact::Unknown => blockers.push(unavail(ReasonCode::PixelConsentUnproven)),
        PermissionFact::Expired => blockers.push(unavail(ReasonCode::PixelConsentExpired)),
    }
}

fn push_local_confirmation(blockers: &mut Vec<Blocker>, fact: LocalConfirmationFact) {
    match fact {
        LocalConfirmationFact::Fresh => {}
        LocalConfirmationFact::Required => {
            blockers.push(perm(ReasonCode::LocalConfirmationRequired));
        }
        LocalConfirmationFact::Pending => {
            blockers.push(perm(ReasonCode::LocalConfirmationPending));
        }
        LocalConfirmationFact::Unavailable => {
            blockers.push(unavail(ReasonCode::LocalConfirmationUnavailable));
        }
        LocalConfirmationFact::Unknown => {
            blockers.push(unavail(ReasonCode::LocalConfirmationUnproven));
        }
        LocalConfirmationFact::Expired => {
            blockers.push(unavail(ReasonCode::LocalConfirmationExpired));
        }
    }
}

const fn unconf(reason: ReasonCode) -> Blocker {
    Blocker {
        state: CapabilityState::Unconfigured,
        reason,
    }
}

const fn perm(reason: ReasonCode) -> Blocker {
    Blocker {
        state: CapabilityState::PermissionRequired,
        reason,
    }
}

const fn unavail(reason: ReasonCode) -> Blocker {
    Blocker {
        state: CapabilityState::Unavailable,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DeserializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> DeserializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::de::DeserializeOwned> DeserializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait DeserializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> DeserializeProbeFallback for DeserializeProbe<T> {}

    struct SerializeProbe<T>(core::marker::PhantomData<T>);

    impl<T> SerializeProbe<T> {
        const fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<T: serde::Serialize> SerializeProbe<T> {
        fn is_implemented(&self) -> bool {
            true
        }
    }

    trait SerializeProbeFallback {
        fn is_implemented(&self) -> bool {
            false
        }
    }

    impl<T> SerializeProbeFallback for SerializeProbe<T> {}

    #[test]
    fn public_projection_types_are_not_serde() {
        assert!(DeserializeProbe::<String>::new().is_implemented());
        assert!(SerializeProbe::<u8>::new().is_implemented());
        assert!(!DeserializeProbe::<RuntimeCapabilityProjection>::new().is_implemented());
        assert!(!SerializeProbe::<RuntimeCapabilityProjection>::new().is_implemented());
        assert!(!DeserializeProbe::<CapabilityStatus>::new().is_implemented());
        assert!(!SerializeProbe::<BindingClaim>::new().is_implemented());
        assert!(!DeserializeProbe::<RuntimeCapabilityFacts>::new().is_implemented());
        assert!(!DeserializeProbe::<HostMode>::new().is_implemented());
        assert!(!DeserializeProbe::<CapabilityId>::new().is_implemented());
        assert!(!DeserializeProbe::<ReasonCode>::new().is_implemented());
        assert!(!DeserializeProbe::<ProjectionRevision>::new().is_implemented());
    }

    #[test]
    fn revision_bounds_reject_empty_long_and_foreign_charset() {
        assert_eq!(
            ProjectionRevision::try_from_opaque("").unwrap_err(),
            RevisionFault::Empty
        );
        let too_long = "a".repeat(MAX_REVISION_BYTES + 1);
        assert_eq!(
            ProjectionRevision::try_from_opaque(&too_long).unwrap_err(),
            RevisionFault::TooLong
        );
        assert_eq!(
            ProjectionRevision::try_from_opaque("rev with space").unwrap_err(),
            RevisionFault::InvalidCharset
        );
        assert_eq!(
            ProjectionRevision::try_from_opaque("postgres://local").unwrap_err(),
            RevisionFault::InvalidCharset
        );
        assert_eq!(
            ProjectionRevision::try_from_opaque("rev-1._OK")
                .unwrap()
                .as_str(),
            "rev-1._OK"
        );
    }

    #[test]
    fn remote_prose_cannot_enter_reason_codes() {
        assert_eq!(
            reject_remote_prose("ECONNREFUSED to 10.0.0.5:443: certificate verify failed"),
            RemoteProseRejected
        );
    }

    #[test]
    fn closed_id_literals_are_stable() {
        assert_eq!(CapabilityId::Workspace.as_str(), "workspace");
        assert_eq!(CapabilityId::AgentTools.as_str(), "agent_tools");
        assert_eq!(CapabilityId::ModelCustomV1.as_str(), "model_custom_v1");
        assert_eq!(
            CapabilityId::ModelSelectionV2.as_str(),
            "model_selection_v2"
        );
        assert_eq!(CapabilityId::ModelSdkGateway.as_str(), "model_sdk_gateway");
        assert_eq!(
            CapabilityId::ModelAccountBridge.as_str(),
            "model_account_bridge"
        );
        assert_eq!(CapabilityId::BrowserControl.as_str(), "browser_control");
        assert_eq!(CapabilityId::NativeControl.as_str(), "native_control");
        assert_eq!(CapabilityId::PixelEgress.as_str(), "pixel_egress");
        assert_eq!(
            CapabilityId::LocalConfirmation.as_str(),
            "local_confirmation"
        );
        assert_eq!(CapabilityId::BackupRestore.as_str(), "backup_restore");
        assert_eq!(CapabilityId::DynamicSso.as_str(), "dynamic_sso");
        assert_eq!(CapabilityId::DevicePairing.as_str(), "device_pairing");
    }

    #[test]
    fn order_has_thirteen_unique_entries() {
        let mut seen = std::collections::BTreeSet::new();
        for id in ORDER {
            assert!(seen.insert(id));
        }
        assert_eq!(seen.len(), 13);
        assert_eq!(ORDER.len(), 13);
        for (index, id) in ORDER.iter().copied().enumerate() {
            assert_eq!(id.ordinal(), index);
        }
    }
}
