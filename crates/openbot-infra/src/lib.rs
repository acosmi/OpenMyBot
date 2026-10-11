//! `openbot-infra` —— 适配器层：PostgreSQL、vault、HTTP safe dialer、provider adapters。
//!
//! # 所有权边界（v3 §5.1 / §6.4 / §10.5 / §14）
//!
//! 负责：
//!
//! - PostgreSQL 访问：连接池、SQL、migration 执行、outbox。**PostgreSQL 17 是唯一数据库语义**
//!   （v3 §14.1，不需要 pgvector）；Rust/PostgreSQL 是 thread、message、run、memory、realtime
//!   cursor、run lock 的唯一真源（v3 §4.1）。
//! - Schema 兼容期只允许 **expand**（v3 §14.3 / repository contract §4）：新表、nullable column、backfill、
//!   index、非破坏性 constraint；禁止 drop / rename / 类型收紧 / 主键改写；无 downgrade migration。
//! - vault：凭据加解密与 `CredentialPrincipalId` 绑定（v3 §6.4）。
//! - HTTP safe dialer：出网前的 DNS / IP 校验与 egress 限制（v3 §10.5），SSRF 面在这里收口。
//! - provider adapters：模型厂商 HTTP/流式协议的翻译层。
//!
//! 明确**不**负责：
//!
//! - 业务规则与 use case 编排 —— 在 `openbot-application`；本 crate 只提供 port 的实现。
//! - 领域不变量判定 —— 在 `openbot-domain`。
//! - Agent loop、AG-UI 事件语义、tool runtime、MCP 会话 —— 在 `openbot-agent`。
//! - 接受来自 transport 的任意 SQL query（v3 §5.2 逐字禁止）。
//! - 任何 phone-home 遥测端点（v3 §16.4 零 phone-home）：OTel exporter 只在管理员显式配置
//!   collector 地址时才建连。
//! - **读环境变量**：连接参数一律由调用方以 [`db::pool::DatabaseConfig`] 显式传入。env 的三档
//!   裁决（v3 §15.4）属于启动 / transport 层，不在本 crate。
//!
//! # 当前状态（G1 + W-1/W-2 + W-3a/W-3b + W-5 batch 6）
//!
//! 已落地的是数据库 schema 层，也就是 v3 §24 G1 判据「28 表/13 migration 映射」的执行面：
//!
//! - [`db::tables`] —— 上游 28 张表的类型化行结构，列名 / 列序 / 可空性 / 类型逐列对应上游
//!   第 13 条 migration（`0012`）跑完之后的终态。
//! - [`db::baseline`] —— fresh install 的 baseline DDL（v3 §14.1），把空库直接建成 0012 终态；
//!   不创建 `0010` / `0011` 已删除的 document / connector 表，对 extension 零操作。
//! - [`db::compat`] —— 迁移边界检查（v3 §14.1「Rust 不接收更早 schema」）。
//! - [`db::schema_facts`] —— schema 事实提取，与 `fixtures/db/schema-0012.json` 同构。
//! - [`db::pool`] —— `deadpool-postgres` 连接池。
//! - [`db::native`] —— Rust-owned 0013–0029，自有 SHA-256 账本与并发施加锁；0021 增加
//!   actor/deployment/tenant scoped UI preference，0022 增加 actor/tenant scoped runtime memory
//!   write control，0023 独立增加 compiled-component human decision state，0024 为 runs 追加
//!   run-wide normalized provider usage，0025追加operator-attested maximum-rate cost upper bound，
//!   0028增加actor-scoped remote AG-UI interrupt/resume与terminal content scrub；0029增加
//!   custom MCP 的显式 private-egress CIDR authority；
//!   均保持 expand-only。
//! - [`repo::IMPLEMENTED_REPOSITORIES`] —— 当前 40 个规划落点全部有物理表与具名 repository；
//!   [`repo::channels::ChannelRepo`] 同时实现 `openbot_application::ChannelReader`。
//! - [`vault::CredentialRepo`] —— credential CAS 轮换/撤销；
//!   [`repo::audit::AuditEventRepo`] —— hash chain/checkpoint；
//!   [`repo::audit::PostgresAuditReader`] —— admin filter/keyset 读面；
//!   [`repo::tools`] —— decision+attempt 同事务与 commit 后 receipt；
//! - [`repo::people_admin`] —— `PeopleAdministration` 的 PostgreSQL 原子适配器：role/access
//!   判定、业务写、auth generation 与 audit 同事务（R40）。
//! - [`repo::tools::PostgresToolJournal`] —— application 的 decision/attempt/capability/outcome
//!   journal；outcome 与 audit 同事务，unknown 固定进 reconciliation（R41）。
//! - [`policy`] —— action policy 权威行、raw+预编译内存快照、同事务 NOTIFY 与专用重连
//!   listener（R56）。
//! - [`store::plugin_user_credential`] —— per-user OAuth 按 `(server, actor)` 的网络前选择、
//!   refresh/access 类型隔离，以及 People 移除后的正常/孤儿 credential 事务退役（R59）。
//! - [`tenant`] —— 五 YAML 有界 loader、checksum、collision-safe PostgreSQL package sync 与
//!   materialized membership/generation/session 原子投影（R60）。
//! - [`thread_directory`] —— OS CSPRNG mint、scope status、同事务 BeginThreadRun 与
//!   LISTEN-before-replay/SSE producer；最终请求路径零 Intelligence fallback（R64–R65）。
//! - [`memory_admin`] —— explicit user_action create/list/correct/supersede/forbid/delete 与
//!   user+exact Bot/thread FTS + structured-tag recall；无 background extraction（R66）。
//! - [`run_runtime`] —— replay-safe dispatch claim、fencing renew/takeover、semantic chunk/terminal、
//!   stale delivered run reconciliation 与 production relay（R67）。
//! - [`intelligence_bundle`] / [`intelligence_import`] —— one-shot signed+encrypted bundle verifier、
//!   target mapping、逐 thread 原子 import、四 cursor、DB 重算 checksum 与 staged FK finalize（R68）。
//! - [`component_catalogue`] —— compiled component治理read与exact build manifest additive sync；
//!   首次published insert与hash-chain audit同事务，既有管理员治理零覆盖（R103）。
//! - [`sandboxed_components`] —— sandboxed source草稿、原子发布/revision、删除与共享治理/audit
//!   同事务；published投影对双表漂移与残缺源fail-closed（R112）。
//!
//! W-7a/W-7b 已在独立 TLS/FFI delta 后落 safe dialer、环境/动态 OIDC、SAML XMLDSig、
//! v2 SSO config、session/group/replay/admin 写面；仍未落地、也不在此假装存在：SAML 外审、
//! Server KMS/HSM、多平台原生发行，以及 G4 的真实 browser/file/shell/MCP/Drive executor。
//! 0016 已把 `thread/run/outbox/memory/import` 的 10 个 repo 与对应物理表同批实现；R64/R65
//! 又接 mint/status、transactional begin 与 SSE live，R66 接 history 与 explicit memory backend。
//! Thread WebSocket 与 terminal/outbox/lease recovery 已由 R67 接上，Intelligence importer 由 R68
//! 接上；真实 Agent consumer/provider producer、remember tool/Memory GUI 仍归后续 G3/G4/G6。

#[cfg(feature = "server-runtime")]
pub mod agent_audit;
#[cfg(feature = "server-runtime")]
pub mod agent_callback;
#[cfg(feature = "server-runtime")]
pub mod agent_tools;
#[cfg(feature = "server-runtime")]
pub mod application_assembly;
pub mod approval_preferences;
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
pub mod artifact_administration;
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
pub use artifact_administration::artifact_read_authority;
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
pub use artifact_administration::artifact_read_lifecycle;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod artifact_bytes;
pub mod artifact_registry;
#[cfg(feature = "server-runtime")]
pub mod artifact_source;
#[cfg(all(
    feature = "server-runtime",
    any(target_os = "macos", target_os = "linux")
))]
pub mod artifact_store;
pub mod auth;
pub mod backup;
#[cfg(feature = "server-runtime")]
mod channel_activity;
#[cfg(feature = "server-runtime")]
pub mod component_catalogue;
#[cfg(feature = "server-runtime")]
pub mod runtime_capability_facts;
// Credential administration includes MCP retirement and belongs to the full shared runtime;
// the standalone Desktop Vault/bootstrap graph only needs the lower-level `vault` module.
#[cfg(feature = "server-runtime")]
pub mod credential_admin;
#[cfg(feature = "server-runtime")]
pub mod custom_model_catalog;
pub mod db;
#[cfg(feature = "server-runtime")]
pub mod gateway_account;
#[cfg(feature = "server-runtime")]
pub mod gateway_authority;
#[cfg(feature = "server-runtime")]
mod gateway_authorization;
#[cfg(feature = "server-runtime")]
pub use gateway_authorization::journal::{
    CallbackErrorKind, CallbackStage, ClosedAttemptReceipt, ControlledCloseReason,
    CreatedAttemptOwner, GatewayAuthorizationCallbackError, GatewayAuthorizationCallbackWaitOwner,
    GatewayAuthorizationJournal, GatewayAuthorizationJournalAck, GatewayAuthorizationJournalError,
    GatewayAuthorizationJournalErrorKind, GatewayAuthorizationJournalRuntimeOwner,
    GatewayAuthorizationVerifiedCodeOwner, RegisteredAttemptOwner, RegistrationAdmissionReceipt,
    RegistrationDispatchError, RegistrationDispatchKind,
};
#[cfg(feature = "server-runtime")]
pub use tokio_util::sync::CancellationToken as GatewayAuthorizationCancellationToken;
#[cfg(feature = "server-runtime")]
pub mod gateway_transport;
#[cfg(feature = "server-runtime")]
pub mod google_drive;
#[cfg(feature = "server-runtime")]
pub mod google_drive_oauth;
#[cfg(feature = "server-runtime")]
pub mod intelligence_bundle;
#[cfg(feature = "server-runtime")]
pub mod intelligence_import;
#[cfg(feature = "server-runtime")]
pub mod mcp;
#[cfg(feature = "server-runtime")]
pub mod mcp_catalog;
#[cfg(feature = "server-runtime")]
pub mod mcp_connections;
#[cfg(feature = "server-runtime")]
pub mod mcp_credentials;
#[cfg(feature = "server-runtime")]
mod mcp_egress;
#[cfg(feature = "server-runtime")]
pub mod mcp_oauth;
#[cfg(feature = "server-runtime")]
pub mod memory_admin;
#[cfg(feature = "server-runtime")]
pub mod model_connections;
#[cfg(feature = "server-runtime")]
pub mod model_dataset;
#[cfg(feature = "server-runtime")]
mod model_runtime;
#[cfg(feature = "server-runtime")]
pub mod net;
#[cfg(feature = "server-runtime")]
pub mod policy;
#[cfg(feature = "server-runtime")]
pub mod provider;
#[cfg(feature = "server-runtime")]
pub mod remote_agui;
#[cfg(feature = "server-runtime")]
pub mod remote_interrupt;
pub mod repo;
#[cfg(feature = "server-runtime")]
pub mod routing;
pub mod run_cost_budget;
#[cfg(feature = "server-runtime")]
pub mod run_runtime;
#[cfg(feature = "server-runtime")]
pub mod sandboxed_components;
#[cfg(feature = "server-runtime")]
pub mod store;
pub mod tenant;
#[cfg(feature = "server-runtime")]
pub mod thread_directory;
#[cfg(feature = "server-runtime")]
pub mod thread_id;
#[cfg(any(feature = "server-runtime", feature = "desktop-local"))]
pub mod thread_listener;
#[cfg(feature = "server-runtime")]
pub mod tool_approval;
#[cfg(feature = "server-runtime")]
pub mod ui_preferences;
#[cfg(any(feature = "server-runtime", feature = "desktop-local-vault"))]
pub mod vault;
