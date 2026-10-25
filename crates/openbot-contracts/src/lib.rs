//! `openbot-contracts` —— 协议层：native/wasm-safe 的 ID、DTO、event、error、schema。
//!
//! # 所有权边界（v3 §5.1 / §5.2 / §5.3）
//!
//! 负责：
//!
//! - 核心 ID 的 string newtype 定义（v3 §5.3 十五个：`DeploymentId` / `TenantId` / `ActorId` /
//!   `BotId` / `ChannelId` / `ThreadId` / `RunId` / `ToolCallId` / `CredentialPrincipalId` /
//!   `ComputerId` / `ComputerGeneration` / `TabId` / `DocumentGeneration` / `PolicyDecisionId` /
//!   `AuditEventId`）。ID 一律不擅自限定为 UUID；创建端可以用 UUIDv7/ULID，兼容端必须接受
//!   上游既有字符串。
//! - 已经真实跨 crate 的内部 contract：`AttemptId` / `CapabilityId` /
//!   `CatalogGeneration` 与 [`auth::AuthGeneration`]。它们刻意不 serde，不扩张上述公开 ID 清单。
//! - 跨边界 DTO、event 族、错误码与 schema。错误以 **code** 穿越边界（repository contract §4a），
//!   状态码与 audit 类型固定（v3 §15.3），文案不在这里。
//! - 唯一一个既编 native 又编 wasm 的 crate：`openbot-ui` 只依赖它（设计系统文档 §13）。
//!
//! 明确**不**负责：
//!
//! - 领域不变量与状态机 —— 在 `openbot-domain`。
//! - use case 编排 —— 在 `openbot-application`。
//! - 任何 I/O：数据库、HTTP、文件、进程 —— 在 `openbot-infra` / `openbot-computer`。
//! - 构造 `AuthContext`。`AuthContext` 只能由 Rust 从 session、连接 peer、数据库 ACL 和资源
//!   映射构造（v3 §5.3）；模型、renderer、MCP server、remote Agent、browser engine 传来的
//!   同名字段一律是普通不可信输入。
//! - 用户可见文案与本地化（repository contract §4a：文案不进 domain / application）。
//!
//! # 当前状态（G1 + people/tool/audit + G3 thread contracts）
//!
//! Phase 0（Evidence Freeze）本 crate 刻意为空；G1 起它承载五个模块：
//!
//! | 模块 | 内容 | 方案出处 |
//! | --- | --- | --- |
//! | [`ids`] | 十五个核心 ID + 三个不 serde 的跨层内部 ID/generation | §5.3 / R47 |
//! | [`auth`] | [`auth::AuthContext`]、[`auth::AuthGeneration`]、[`auth::Role`]、受限构造入口 | §5.3 / §5.2 / R47 |
//! | [`error`] | [`error::AppError`]、稳定 code、HTTP status、audit 类型 | §15.3 |
//! | [`command`] | [`command::AppCommand`] / `AppReply` / `SubscriptionRequest` / `AppEvent`，含 R64 thread mint/status | §5.2 / §4.1 |
//! | [`desktop`] | Desktop structured stream command names、closed frame 与 open/close receipt | §13.2–§13.4 / R146–R147 |
//! | [`people`] | current user / admin status / people page 与 person 公开 DTO | §6.2 / R40 |
//! | [`audit`] | 管理员 audit event/page DTO 与 JavaScript 毫秒时间 wire | §8.6 / R56 |
//! | [`tool`] | Agent tool invocation 与脱敏结果；没有 actor/policy/target 自报字段 | §8.1 |
//! | [`memory`] | explicit memory scope/provenance/lifecycle/recall DTO；wire 无 owner/origin 自报 | §4.3 / R66 |
//! | [`components`] | compiled component治理record、build manifest/catalogue与Quote+Cards+Charts参数schema | §3.3 / R103–R105 |
//! | [`sandboxed`] | sandboxed draft/published source、sample与发布响应的closed wire | §3.3 / R112 |
//! | [`screen`] | actor/generation/host-bound ScreenSession request与Debug脱敏ticket | §12.2–§12.4 / R188 |
//! | [`telemetry`] | 关联字段、metrics label 白名单、[`telemetry::Redacted`] | §16.4 |
//!
//! 「没有 parity ledger 条目背书的类型不进这里」这条规矩**继续有效**：W-3a 只在 G1 的
//! channel/health 之外追加 fixed-upstream people slice；R64 已加 thread request/reply，thread live
//! 订阅与 browser 协议仍是后续工作，届时随各自 ledger 条目一起加。本 crate 里凡是与上游行为对齐的取值
//! （如 [`command::MAX_CHANNEL_PAGE`]）都在注释里标了 parity 出处，新增项同理 —— 把新增
//! 写成"当前行为"是 v2 审计里最重的一类错误（§28.1 R1）。
//!
//! # 依赖面为什么这么窄
//!
//! 本 crate 必须编到 `wasm32-unknown-unknown`（`openbot-ui` 是 Leptos CSR/WASM 且只依赖它）。
//! 所以依赖只有 `serde` / `serde_json` / `thiserror` / `time` / 纯 Rust `sha2`；`sha2` 只做
//! ThreadIdentity fingerprint，随机源仍在 infra。`serde_json::Value` 只出现在封闭
//! `InvokeTool` 的 arguments 字段，actor/policy/target 仍无自报入口。**禁止**引入 `tokio` /
//! `axum` / `tokio-postgres` 或任何做 I/O 的 crate ——
//! 那会让整个 GUI 编译失败，或者更糟：编过了但在浏览器里运行期炸。闸门是
//! `cargo check -p openbot-contracts --target wasm32-unknown-unknown`，它必须与
//! `cargo test` 同批次跑：只跑 native 那一半，wasm 破裂要到 G6 打包时才会被发现。
//!
//! # feature
//!
//! - `testkit`（默认**关**）：打开 [`auth::AuthContext::for_test`]。生产 transport 的
//!   feature 图里没有它，于是那条测试构造器根本不会被编译进发行物。

// 本 crate 的每个公开条目都必须有中文文档：协议层是跨 crate 的契约面，一个没有文档的
// 公开类型等于一个只有作者知道语义的契约。用 deny 而不是 warn —— warn 在 `cargo test`
// 的输出里会被淹没，只有 clippy 的 `-D warnings` 拦得住，那是半道闸门。
#![deny(missing_docs)]

pub mod agent;
pub mod approval_preferences;
pub mod artifact_read;
pub mod artifact_read_protocol;
pub mod artifacts;
pub mod audit;
pub mod auth;
pub mod begin_thread_run_wire;
pub mod budget;
pub mod command;
pub mod components;
pub mod credential_admin;
pub mod custom_model_catalog;
pub mod desktop;
pub mod engine;
pub mod error;
pub mod identity_provider;
pub mod ids;
pub mod intelligence;
pub mod mcp;
pub mod memory;
pub mod model_connections;
pub mod people;
pub mod policy;
pub mod reconciliation;
pub mod remote_interrupt;
pub mod request_binding;
pub mod recovery;
pub mod revision;
pub mod runtime_capabilities;
pub mod sandboxed;
pub mod screen;
mod secret_text;
pub mod telemetry;
pub mod text;
pub mod tool;
pub mod ui;
pub mod versioned_model_selection;

// R425 非 Serde 受信宿主接口。
pub use artifact_read::PendingArtifactReadBuffer;
pub use custom_model_catalog::{
    CustomModelCatalogEntry, CustomModelCatalogPage, CustomModelCatalogPageRequest,
    CustomModelCatalogReply, CustomModelCatalogReplyAllocation, CustomModelCatalogReplyCancel,
    CustomModelCatalogReplyRegistration,
};
pub use request_binding::{
    ArtifactReadCurrentError, ArtifactReadCurrentTarget, ArtifactReadRecordFacts,
    ArtifactReadTailWitness,
};
pub use request_binding::{
    BorrowedServerSessionEpoch, HostRequestBindingError, HostRequestBindingGuard,
    HostRequestBindingIdentity, HostRequestBindingKind, MAX_SERVER_SESSION_EPOCH_LOOKUP_BYTES,
    RequestBindingAttachError, RequestBindingIssuer, RequestBindingOwnerLease,
    RequestBindingOwnerObservation, ServerSessionBindingIdentity, VerifiedHostRequestBinding,
};
pub use recovery::{
    RecoveryAdmissionLease, RecoveryAdmissionPurpose, RecoveryAdmissionWitness,
    RecoveryHostReadPort,
};
pub use request_binding::{
    CustomModelCatalogHostObservation, CustomModelCatalogHostObservationParts,
    CustomModelCatalogHostTailFactory, CustomModelCatalogHostTailWitness,
    CustomModelCatalogHostTarget, CustomModelCatalogSessionFacts,
};
