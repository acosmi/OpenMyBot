//! `openbot-agent` —— Agent 运行时：built-in loop、AG-UI、tool runtime、MCP、connectors。
//!
//! # 所有权边界（v3 §5.1 / §7 / §8 / §9）
//!
//! 负责：
//!
//! - built-in Agent loop 的宿主：每 thread 一个 foreground actor 串行处理，后台工作是独立
//!   durable run（v3 §7.2）。**reducer 本身是 `openbot-domain` 的纯函数**，本 crate 只负责
//!   把 effect 真正跑起来并把结果喂回去。
//! - AG-UI 事件族的编解码与 remote AG-UI（v3 §7.5）；retry / cancel / budget / commit（v3 §7.4）。
//! - tool runtime：工具元数据（v3 §8.2）、CEL 求值调用点（v3 §8.3）、content governance
//!   （v3 §8.4）、approval（v3 §8.5）、audit 事件产出（v3 §8.6）。
//! - MCP runtime（v3 §9.1 首版范围）、连接生命周期、catalog 与 stale grant、OAuth（v3 §9.2–§9.4）、
//!   Google Drive REST connector（v3 §9.5，**不是** MCP）、skills 与 tool discovery（v3 §9.6）。
//!
//! 明确**不**负责：
//!
//! - 决定"这次工具调用允不允许" —— 判定规则在 `openbot-domain`，执行管线的顺序保证在
//!   `openbot-application`（v3 §8.1）。本 crate 不得成为第二个策略脑。
//! - 数据库写入与凭据解密 —— 在 `openbot-infra`。
//! - 浏览器 / 文件 / shell 的实际执行与隔离 —— 在 `openbot-computer`。
//! - 信任 MCP server、remote Agent 或模型回传的身份字段（v3 §5.3：一律视为普通不可信输入）。
//!
//! # 当前状态
//!
//! [`AgentToolGateway`] 铸造 call ID/sequence，并把调用交给同一个 `ApplicationService`；
//! production built-in host 可注入 [`AuthorizedAgentToolGateway`] 以在每次 effect 前重读 DB ACL。
//! RMCP/Drive/browser/file/shell executor 仍未因内建 remember tool 而完成。

#![deny(missing_docs)]

pub mod agui;
mod gateway;
mod provider_router;
mod remote_provider;
mod retry;
mod runtime;

pub use agui::{
    AGUI_EVENT_TYPES, AGUI_SCHEMA_VERSION, AguiDecoder, AguiEvent, AguiProtocolError, AguiRole,
    MAX_AGUI_COLLECTION_ITEMS, MAX_AGUI_EVENT_BYTES, MAX_AGUI_RUN_INPUT_BYTES,
    apply_patch as apply_agui_json_patch, encode_run_agent_input,
};
pub use gateway::{
    AgentToolGateway, AgentToolInvokeError, AgentToolInvoker, AgentToolReply, AgentToolScheduling,
    AuthorizedAgentToolGateway, MAX_AGENT_TOOL_RESOURCE_LOCKS, NoAgentToolInvoker,
    RemoteAgentToolInvoker,
};
pub use provider_router::ProviderRouter;
pub use remote_provider::RemoteAguiProvider;
pub use retry::{RetryingProvider, RetryingProviderConfig};
pub use runtime::{
    AGENT_SHUTDOWN_DEADLINE, AutomationSamplingPorts, BuiltInAgentConfig, BuiltInAgentRuntime,
    BuiltInRunPorts, DEFAULT_AGENT_CONCURRENCY, DEFAULT_AGENT_QUEUE_CAPACITY,
    DEFAULT_AGENT_TOOL_CONCURRENCY, DEFAULT_LEASE_RENEW_INTERVAL, DEFAULT_RUN_DEADLINE,
    MAX_AGENT_TOOL_CONCURRENCY, TOOL_STEP_CAP,
};
