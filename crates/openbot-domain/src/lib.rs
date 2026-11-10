//! `openbot-domain` —— 纯领域层：领域状态、不变量、policy 类型、Agent reducer。
//!
//! # 所有权边界（v3 §5.1 / §7.2 / §8.1）
//!
//! 负责：
//!
//! - 领域状态与不变量本身（thread / run / tool call / lease / generation 的合法迁移）。
//! - policy 类型与**判定本身**：决策输入、决策结果、refusal 原因的类型化表达，以及 CEL
//!   求值器。落点由 Phase 0 的 fixtures 台账钉死（`fixtures/MANIFEST.yaml` 的
//!   `policy-cel-corpus`：`owner: openbot-domain`，`target: … -> openbot_domain::policy::cel`）。
//!   Phase 0 时本段曾写作「CEL 求值器在 `openbot-infra`」，那是一句没有台账支撑的推断，
//!   与同期冻结的 fixtures 台账相互矛盾，G2 落地时按台账更正。
//! - **Agent reducer 必须 pure**（v3 §7.2 / repository contract §4）：`reduce(state, event) -> (state, effects)`。
//!   DB、provider、MCP、browser、file、shell 全都是 effect —— reducer 只描述它们，永不执行。
//! - 工具执行管线（v3 §8.1）里属于纯判定的那几段：validation、effect 分类、outcome 与
//!   `commit_state` 的状态迁移规则。
//!
//! 明确**不**负责：
//!
//! - 任何 I/O、时钟、随机数与 async runtime。纯函数是可确定性重放（v3 §20.1 shadow Agent
//!   重放录制 stream）的前提，一旦掺进环境依赖，golden trace 就不可信。
//! - use case 编排与事务边界 —— 在 `openbot-application`。
//! - SQL、连接池、HTTP、provider 协议细节 —— 在 `openbot-infra`。
//! - 用户可见文案与本地化（repository contract §4a）。错误与拒绝理由以**类型化的 code** 穿越边界。
//!
//! ## 唯一一处线程，以及它为什么在这里
//!
//! 上面那条「不负责」清单在 Phase 0 还写着「线程」。G2 落 CEL 求值器时**实测**推翻了它：
//! `cel 0.14.3` 的解析器是 antlr4rust 递归下降，栈消耗随括号嵌套线性增长，本机 debug 构建下
//! 每 MiB 栈约扛 6 层，~1 MiB 的 Windows 主线程在**第 6 层**就把栈打穿 —— 而 Rust 的栈溢出是
//! abort，不是可捕获的 panic。策略表达式来自管理员可写的列，于是「一条写歪的规则打死进程」
//! 是一条真实路径。
//!
//! 把这条约束交给调用方（「请在栈够大的线程上调用」）就是本仓反复判定为**不是闸门**的那种
//! 形态：答案取决于跑在哪个线程上。所以 [`policy::cel::compile`] 自己拉一条栈大小写死的
//! 线程做解析、立即 join。它没有引入并发（调用方观察不到任何异步性），也没有引入不确定性
//! （同样的输入同样的输出），只是把「还剩多少栈」这个环境变量移出等式。求值不需要同样的
//! 待遇，实测理由见 `policy::cel::guard` 的模块文档。
//!
//! # G2 状态（Data/Auth/Governance，W11–20）
//!
//! | 模块 | 内容 | 方案出处 |
//! | --- | --- | --- |
//! | [`policy`] | `ActionPolicy`、CEL 求值器与两个上游全局函数、deny-before-allow、迁移 preflight | §8.3 |
//! | [`identity`] | email 规范化、角色与 admin floor、撤权、group → membership 投影、session 寿命 | §6.1–§6.3 / §6.5 |
//! | [`vault`] | v1 信封读兼容、v2 AEAD 的 AAD 绑定、轮换状态机 | §6.4 |
//! | [`audit`] | hash chain、checkpoint、payload allowlist、retention 边界 | §8.6 |
//! | [`components`] | compiled component publication/withholding/data-function纯判定 | §3.3 |
//! | [`tool`] | tool metadata、effect 分类、decision → attempt → outcome 状态机、approval 绑定 | §8.1 / §8.2 / §8.5 |

// 领域层的每个公开条目都必须有中文文档：不变量写在类型上，而不变量的**理由**只能写在文档里。
#![deny(missing_docs)]

pub mod agent;
pub mod artifact;
pub mod artifact_cleanup;
pub mod audit;
pub mod automation;
pub mod backup;
pub mod channel;
pub mod components;
pub mod content_governance;
pub mod identity;
pub mod memory;
pub mod policy;
pub mod remote_callback;
pub mod routing;
pub mod run;
/// Pure internal runtime capability projection.
pub mod runtime_capabilities;
pub mod text;
pub mod thread;
pub mod tool;
/// Pure internal update compatibility preflight.
pub mod upgrade_preflight;
pub mod vault;
