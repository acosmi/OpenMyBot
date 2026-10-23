//! [`ServerConfig`] —— Server 侧那一份启动配置。
//!
//! # 边界：这里放什么，不放什么
//!
//! 放的是 `parity/env.yaml` 里 `target: "openbot-server::config::ServerConfig"` 的那些条目。
//! 刻意**不**放的三类：
//!
//! - `DATABASE_URL` —— 台账把它指给 `openbot-infra::db::DatabaseConfig`。同一个变量两个
//!   解析器就是两个答案，而先坏掉的那个不会有人发现。
//! - 认证面（session secret、`KEY_ENCRYPTION_KEY`、三家 OAuth、管理员名单、可信来源）
//!   —— 在 `openbot_infra::auth::config`。
//! - `openbot-computer` / `openbot-agent` 归属的那一大批（容器镜像、超时、provider key、
//!   run 预算）—— 属 G4/G5。本模块只收 Server 作为**调用方**要用的那六个 computer 端点变量。
//!
//! # `OPENBOT_ENV` 只在这里解析一次
//!
//! 它现在的唯一用途是决定"示例 `KEY_ENCRYPTION_KEY` 放不放行"，而那个判定住在
//! `openbot-infra`。两个 crate 是兄弟（谁也不依赖谁），所以**不能**共用一个类型。
//!
//! 解法与 `crate::readiness` 模块文档里那段 `DataMigrationVerdict -> ReadinessVerdict`
//! 完全同构：解析只有一处（这里），接线层写一次**穷举** `match` 把它映射过去：
//!
//! ```ignore
//! let policy = match config.deployment_environment {
//!     DeploymentEnvironment::Production => ExampleKeyPolicy::Reject,
//!     DeploymentEnvironment::Development => ExampleKeyPolicy::Allow,
//! };
//! ```
//!
//! 穷举是重点：任何一侧新增变体，接线层当场编译失败，而不是悄悄落进某个 `_ =>`。
//!
//! # 与上游 `server/src/config.ts` 的**已知偏差**
//!
//! 逐条都以本机实跑上游源码为准，理由写在各自的字段文档里，交付报告里另有一张总表。
//!
//! | 项 | 上游 | 这里 |
//! | --- | --- | --- |
//! | `PORT` | `Number.parseInt(… ?? "3001", 10)`，`"3001abc"` 读成 `3001`，`"abc"` 读成 `NaN` | 整数解析，读不出就拒绝启动 |
//! | `OPENBOT_PUBLIC_URL` | `optional()`，完全不校验 | 必须是绝对 `http`/`https` URL（它要回答 `Secure` cookie 那个问题） |
//! | `AGENT_COMPUTER_URL` / `COMPUTER_SUPERVISOR_URL` | `new URL()`，任意 scheme | 只收 `http`/`https` |
//! | `AGENT_COMPUTER_POLICY` | 解析 JSON + 校验 shape，非法即拒绝启动 | 同上（G2 已闭合，见 [`crate::config::policy`]） |
//! | 报错方式 | 抛第一个就停 | 一次列全（见 [`crate::config::error`]） |

use core::num::NonZeroU32;

use openbot_domain::audit::retention::{RetentionPolicy, parse_retention_days};
use openbot_domain::policy::ActionPolicy;

use crate::config::address::DeploymentAddress;
use crate::config::agent::{
    AgentBudgets, ManagedProviderConfig, PackageOpenAiProviderConfig, parse_agent_config,
};
use crate::config::env::{self, EnvMap};
use crate::config::error::{ConfigError, ConfigProblem, Expectation};
use crate::config::migration::check_migrated_env_vars;
use crate::config::policy::parse_action_policy;
use crate::config::secret::Secret;
use crate::config::transport::PublicTransport;

/// 未设 `PORT` 时监听的端口。
///
/// `3001` 取自上游 `server/src/index.ts::port` 的 `?? "3001"`，`.env.example` 也写着同一个数。
/// 它**不在** `config.ts` 里 —— 上游那份配置模块压根不读 `PORT`，读它的是进程入口。
pub const DEFAULT_PORT: u16 = 3001;

/// 未设 `TENANT_PACKAGE_DIR` 时的租户包目录。
///
/// 取自上游 `config.ts::loadConfig` 的 `?? "../examples/fintech"`，相对 `server/` 解析。
/// 保留这个相对路径而不是换成绝对路径：它同时是 `DEPLOYMENT_ID` 缺省时 thread 指纹的
/// 顶替来源（v3 §20.3），换掉它等于换掉既有 thread 的归属判定。
pub const DEFAULT_TENANT_PACKAGE_DIR: &str = "../examples/fintech";

/// 部署形态。**缺省是生产**，这是相对上游的一次有意翻转。
///
/// 上游那个 Node 侧的同类变量（见 [`crate::config::migration`] 的改名表）未设即为空，
/// 于是"唯一需要它管住的那个部署"恰恰是它放过的那个：一台手写 `.env` 的裸机，
/// 什么都没设，于是示例 `KEY_ENCRYPTION_KEY` 被放行。
///
/// 这里缺省即生产语义，只有**显式**写 `development` 才放行示例 key。默认方向反过来之后，
/// 忘记配置的后果从"静默不安全"变成"启动就拒绝"。
///
/// 它对单用户、cookie、policy 等**一切**其它安全判断仍然无效（v3 §6.1 逐字）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeploymentEnvironment {
    /// 生产。缺省值。
    Production,
    /// 开发。**只有显式写出来才成立。**
    Development,
}

impl DeploymentEnvironment {
    /// 稳定的线上取值。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }

    /// 从环境映射解析。未设 → [`DeploymentEnvironment::Production`]。
    ///
    /// 取值**大小写敏感、只收两个字面量**。写了别的（`Production`、`prod`、`staging`）
    /// 一律拒绝启动，而不是"认不出就当生产"。
    ///
    /// 后者听上去更宽容，代价却是：一个想开发态跑、把值写成 `dev` 的人，会拿到一个
    /// 完全正确的生产部署，**没有任何提示**，然后花半小时找"为什么示例 key 被拒"。
    /// 拒绝是唯一一个会把"你写的这个值我不认识"说出口的选项。
    fn parse(env_map: &EnvMap) -> Result<Self, ConfigProblem> {
        match env::optional(env_map, "OPENBOT_ENV") {
            None | Some("production") => Ok(Self::Production),
            Some("development") => Ok(Self::Development),
            Some(_) => Err(ConfigProblem::Malformed {
                variable: "OPENBOT_ENV",
                expectation: Expectation::DeploymentEnvironmentName,
            }),
        }
    }
}

/// 审计留存窗口（v3 §8.6）。
///
/// # 为什么不是 `Option<u32>`
///
/// `Option<u32>` 里 `Some(0)` 是个**合法构造但语义不存在**的值："保留 0 天"要么是
/// "立刻删光"要么是"永久保留"，取决于读的人怎么想 —— 上游正是用一句注释挡住它的
/// （`auditRetentionDays` 的 doc 写着"a typo that silently became 0 would delete the trail"）。
/// 用 [`NonZeroU32`] 之后，那个歧义值在类型层面构造不出来。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditRetention {
    /// 永久保留。**未设时的缺省**。
    ///
    /// 上游逐字：删掉别人的审计轨迹是两种失败里更糟的那个，没想过留存策略的部署
    /// 应当先全留着。
    Forever,
    /// 保留这么多天。
    Days(NonZeroU32),
}

/// Bot computer 的接入形态（上游 `config.ts::ComputerConfig` 的两个变体）。
///
/// 用 enum 而不是"一个 struct 带两个可空 URL"：上游 `computerConfig` 的判定是
/// `COMPUTER_SUPERVISOR_URL` **优先**，两个都没有则整个能力不挂载。可空字段的写法会让
/// "两个都设了" 变成一个需要每个消费点各自记得处理的状态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComputerProvider {
    /// 每个 Bot 一个容器，由 supervisor 分配。`COMPUTER_SUPERVISOR_URL` 设了就是它。
    Docker {
        /// supervisor 的 base URL。
        base_url: DeploymentAddress,
        /// 调用 supervisor 用的 bearer token。
        ///
        /// 上游 supervisor 进程自己未设即 `process.exit(1)`（它持有 Docker socket =
        /// 主机 root），所以两侧必须是同一个值。
        supervisor_token: Option<Secret>,
    },
    /// 所有 Bot 共用一台 computer。只设了 `AGENT_COMPUTER_URL` 时是它。
    Shared {
        /// computer 的 base URL。
        base_url: DeploymentAddress,
    },
}

/// Server 作为**调用方**看到的 computer 配置。
///
/// 整体为 `None` 表示这项能力**没挂载**，而不是挂载了但坏着 —— 上游
/// `DeploymentConfig.computer` 的注释逐字写着这条：没配置的能力应当是缺席的，不是坏的。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputerConfig {
    /// 接入形态。
    pub provider: ComputerProvider,
    /// 允许 Bot 浏览私网地址。
    ///
    /// 判据是字符串**恒等** `"true"`（上游 `optional(...) === "true"`），不是布尔解析：
    /// `"1"` / `"yes"` / `"TRUE"` 都不算。这条要逐字保留 —— 它是个只该在本机打开的开关，
    /// 而"宽容的布尔解析"会让一个写着 `AGENT_COMPUTER_ALLOW_PRIVATE_HOSTS=1` 的部署
    /// 以为自己关着，其实开着。
    pub allow_private_hosts: bool,
    /// 每次调用 computer 都要出示的密钥。
    pub token: Option<Secret>,
    /// 这个部署允许 Bot 在它的 computer 上做什么。
    ///
    /// 在**启动期**解析并校验（`AGENT_COMPUTER_POLICY`，见 [`crate::config::policy`]）：
    /// 非法 JSON 或错 shape 一律拒绝启动，不回落到缺省。理由是上游写下的那条 ——
    /// 一个写了规则又打错了的操作员，否则会得到一个照常跑着、并且静默放行了他刚刚
    /// 想禁止的那件事的部署。
    ///
    /// `None` = 没配这个变量，由 policy 存储层决定用什么（v3 §8.3：新安装没有隐式
    /// `allow: ["true"]`，在管理员写下第一条规则之前所有 acting tool 一律 deny）。
    /// 它**不是**"放行一切"。
    ///
    /// # 一个反直觉的边界，读到这里的人请留意
    ///
    /// 这个变量只在**至少配了一个 computer 地址**时才被解析（上游
    /// `config.ts::computerConfig` 提前 return 在 `actionPolicy()` 调用之前，本轮实测）。
    /// 于是一份写错了策略、但还没配 computer 地址的环境**照常启动** —— 直到某天有人
    /// 配上地址那一刻才会被拒。照搬这条是有意的：computer 能力整体没挂载时没有任何东西
    /// 会读这份策略，为一个不会被使用的值拒绝启动，等于让一个能正常工作的部署起不来。
    pub action_policy: Option<ActionPolicy>,
}

/// Explicit trusted startup installation label; format validation grants no installation authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfiguredServerJournalInstallationId {
    raw: String,
}

impl ConfiguredServerJournalInstallationId {
    pub(crate) fn as_str(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Debug for ConfiguredServerJournalInstallationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConfiguredServerJournalInstallationId")
            .field(&"<redacted>")
            .finish()
    }
}

/// Server 启动配置。
#[derive(Debug)]
pub struct ServerConfig {
    /// Original owner-held recovery configuration. It is linear and redacted;
    /// this source seal alone is not a startup, database or Current grant.
    #[cfg(unix)]
    pub recovery_host: Option<openbot_infra::recovery_control::VerifiedServiceRecoveryHost>,
    /// 监听端口。缺省 [`DEFAULT_PORT`]。
    pub port: u16,
    /// 部署形态。见 [`DeploymentEnvironment`]。
    pub deployment_environment: DeploymentEnvironment,
    /// 本部署的名字，进入它铸造的每个 thread id 的 6 字节指纹（v3 §20.3）。
    ///
    /// 未设时由租户包的 id 顶替（那一步在 tenant package 加载之后，不在本模块）。
    /// 改它等于放弃对既有 thread 的 `owns` 判定，所以迁移 preflight 必须拒绝与旧库不一致
    /// 的值 —— 那是迁移工具的活，本模块只负责把值原样带出来。
    pub deployment_id: Option<String>,
    /// Explicit canonical startup label; absence leaves the authorization journal unavailable.
    pub gateway_authorization_installation_id: Option<ConfiguredServerJournalInstallationId>,
    /// 本部署对外的公共地址，无尾斜杠。
    ///
    /// **唯一**公共地址来源（v3 §15.4：它接替了上游那个 auth 专用的旧变量）。
    /// 由配置给出而不是从 `Host` 头拼：一个用请求头拼出来的 redirect URI，
    /// 是攻击者有份参与决定的（上游 `DeploymentConfig.publicUrl` 的 doc 原话）。
    ///
    /// 它同时是 [`ServerConfig::public_transport`] 的唯一输入。
    pub public_url: Option<DeploymentAddress>,
    /// Secret shared only with the explicitly configured same-machine HTTPS terminator.
    pub tls_proxy_secret: Option<Secret>,
    /// 浏览器端 App 的地址，无尾斜杠。
    ///
    /// 与 [`ServerConfig::public_url`] 是**两个**地址：本地开发时 App 由 Vite 托管在自己的
    /// 端口上，API 在另一个端口；OAuth 回调落在 API 上，之后必须把人送回一个**页面**。
    ///
    /// 回落链逐字照搬上游：`OPENBOT_APP_URL` → `TRUSTED_ORIGINS` 的第一项 →
    /// `OPENBOT_PUBLIC_URL`。上游链尾还有一节（那个已改名的 auth 地址变量），
    /// 改名之后它与 `OPENBOT_PUBLIC_URL` 合并成同一节。
    ///
    /// 类型是 `String` 而不是 [`DeploymentAddress`]：这一节可能来自 `TRUSTED_ORIGINS`，
    /// 而那是 auth 侧的可信来源清单，上游对它同样不做 URL 校验。在本模块把它收紧，
    /// 等于让一个能正常跑的上游部署在迁移时莫名其妙起不来。
    pub app_url: Option<String>,
    /// 已构建前端的所在目录；设了才由本进程托管它。
    ///
    /// 容器镜像里设，开发态不设 —— 开发态由 Vite 托管前端并反代 API，
    /// 于是 server 保持纯 API，没有任何东西会遮住一条路由。
    pub app_dist_dir: Option<String>,
    /// Explicit trusted startup-only artifact byte directory, verified by its real descriptor.
    /// Absence leaves the saving dependency unavailable; no root is inferred from a tenant.
    pub artifact_root: Option<std::path::PathBuf>,
    /// 租户包目录。缺省 [`DEFAULT_TENANT_PACKAGE_DIR`]。
    pub tenant_package_directory: String,
    /// 审计留存窗口。
    pub audit_retention: AuditRetention,
    /// Bot computer 接入。`None` = 该能力未挂载。
    pub computer: Option<ComputerConfig>,
    /// Agent stall/absolute budgets；即使 provider 未配置也有权威默认。
    pub agent_budgets: AgentBudgets,
    /// Package built-in Bot 的 OpenAI transport 与 environment fallback；model/key id 来自包。
    pub package_openai_provider: PackageOpenAiProviderConfig,
    /// Environment-managed provider；None 时 Server 保留明确 fail-closed consumer。
    pub managed_provider: Option<ManagedProviderConfig>,
}

impl ServerConfig {
    /// 从唯一环境快照解析，不读取进程环境。既有字段仍按原纯解析器处理；
    /// 必需的 `WROK_BOT_RECOVERY_CONFIG` 另外经 Infra 原受信文件 producer
    /// 真实核验 owner、FD 和闭键内容，不把一个路径当作宿主授权。
    ///
    /// # 顺序是契约的一部分
    ///
    /// 第一步永远是 [`check_migrated_env_vars`]。理由：一份还带着退役变量的 `.env`，
    /// 它别的地方大概率也还是上游那一套，先报一堆"值不对"只会把真正的信息
    /// （"你这份配置是上游的，需要迁移"）埋在噪音底下。
    ///
    /// # Errors
    ///
    /// 把**所有**问题一次性收进 [`ConfigError`]，不是遇到第一个就停。
    pub fn from_env_map(env_map: &EnvMap) -> Result<Self, ConfigError> {
        let mut problems = check_migrated_env_vars(env_map);

        let deployment_environment = match DeploymentEnvironment::parse(env_map) {
            Ok(value) => value,
            Err(problem) => {
                problems.push(problem);
                // 占位值只在"已经要报错了"的路径上被用到，永远不会进入返回的配置。
                DeploymentEnvironment::Production
            }
        };

        let port = match env::optional(env_map, "PORT") {
            None => DEFAULT_PORT,
            Some(raw) => match raw.parse::<u16>() {
                Ok(value) => value,
                Err(_) => {
                    problems.push(ConfigProblem::Malformed {
                        variable: "PORT",
                        expectation: Expectation::TcpPort,
                    });
                    DEFAULT_PORT
                }
            },
        };

        let gateway_authorization_installation_id =
            match env_map.get("OPENBOT_GATEWAY_AUTH_INSTALLATION_ID") {
                None => None,
                Some(raw)
                    if raw.len() == 64
                        && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
                {
                    Some(ConfiguredServerJournalInstallationId { raw: raw.clone() })
                }
                Some(_) => {
                    problems.push(ConfigProblem::Malformed {
                        variable: "OPENBOT_GATEWAY_AUTH_INSTALLATION_ID",
                        expectation: Expectation::GatewayAuthorizationInstallationId,
                    });
                    None
                }
            };

        let public_url = parse_optional_address(env_map, "OPENBOT_PUBLIC_URL", &mut problems);
        let tls_proxy_secret =
            super::transport::parse_tls_proxy_secret(env_map, public_url.as_ref(), &mut problems);
        let audit_retention = parse_audit_retention(env_map, &mut problems);
        let computer = parse_computer(env_map, &mut problems);
        let (agent_budgets, package_openai_provider, managed_provider) =
            parse_agent_config(env_map, &mut problems);

        // 回落链在 `public_url` 之后算：它的最后一节就是公共地址的原串。
        let app_url = env::optional(env_map, "OPENBOT_APP_URL")
            .map(str::to_owned)
            .or_else(|| {
                env::comma_separated(env_map, "TRUSTED_ORIGINS")
                    .into_iter()
                    .next()
            })
            .or_else(|| {
                public_url
                    .as_ref()
                    .map(|address| address.as_str().to_owned())
            })
            .map(|value| env::strip_trailing_slashes(&value).to_owned());

        #[cfg(unix)]
        let recovery_host = match env::optional(env_map, "WROK_BOT_RECOVERY_CONFIG") {
            None => {
                problems.push(ConfigProblem::Malformed {
                    variable: "WROK_BOT_RECOVERY_CONFIG",
                    expectation: Expectation::NonEmptySecret,
                });
                None
            }
            Some(path) => match openbot_infra::recovery_control::load_service_recovery_host_from_config(
                std::path::Path::new(path),
            ) {
                Ok(host) => Some(host),
                Err(_) => {
                    // Preserve the existing closed, value-free transport
                    // vocabulary. The original expectation label is coarse:
                    // this is a private configuration object, not a policy.
                    problems.push(ConfigProblem::Malformed {
                        variable: "WROK_BOT_RECOVERY_CONFIG",
                        expectation: Expectation::ActionPolicyObject,
                    });
                    None
                }
            },
        };
        // The registered real producer is Unix. Unsupported hosts cannot
        // return a usable ServerConfig or fall back to an ungated startup.
        #[cfg(not(unix))]
        problems.push(ConfigProblem::Malformed {
            variable: "WROK_BOT_RECOVERY_CONFIG",
            expectation: Expectation::ActionPolicyObject,
        });

        if let Some(error) = ConfigError::new(problems) {
            return Err(error);
        }

        #[cfg(unix)]
        let recovery_host = recovery_host.ok_or_else(|| {
            ConfigError::new(vec![ConfigProblem::Malformed {
                variable: "WROK_BOT_RECOVERY_CONFIG",
                expectation: Expectation::ActionPolicyObject,
            }]).expect("a fixed nonempty problem list")
        })?;

        Ok(Self {
            #[cfg(unix)]
            recovery_host: Some(recovery_host),
            port,
            deployment_environment,
            deployment_id: env::optional(env_map, "DEPLOYMENT_ID").map(str::to_owned),
            gateway_authorization_installation_id,
            public_url,
            tls_proxy_secret,
            app_url,
            app_dist_dir: env::optional(env_map, "APP_DIST_DIR").map(str::to_owned),
            artifact_root: env::optional(env_map, "OPENBOT_ARTIFACT_ROOT")
                .map(std::path::PathBuf::from),
            tenant_package_directory: env::optional(env_map, "TENANT_PACKAGE_DIR")
                .unwrap_or(DEFAULT_TENANT_PACKAGE_DIR)
                .to_owned(),
            audit_retention,
            computer,
            agent_budgets,
            package_openai_provider,
            managed_provider,
        })
    }

    /// 公共传输的安全档位 —— session cookie 的 `Secure` 与 readiness 的
    /// `insecure_transport` 都由它单点决定（v3 §6.3）。
    #[must_use]
    pub fn public_transport(&self) -> PublicTransport {
        PublicTransport::classify(self.public_url.as_ref())
    }

    /// Produce the request gate from authenticated deployment mode and reviewed proxy inputs.
    /// A public URL alone never proves that a request arrived over TLS.
    #[must_use]
    pub fn transport_policy(&self, single_user: bool) -> super::transport::TrustedTransportPolicy {
        super::transport::TrustedTransportPolicy::from_configuration(
            self.public_url.as_ref(),
            self.tls_proxy_secret.clone(),
            single_user,
        )
    }
}

/// 解析一个可选的绝对 `http`/`https` 地址，失败时记一条问题。
fn parse_optional_address(
    env_map: &EnvMap,
    variable: &'static str,
    problems: &mut Vec<ConfigProblem>,
) -> Option<DeploymentAddress> {
    let raw = env::optional(env_map, variable)?;
    match DeploymentAddress::parse(raw) {
        Ok(address) => Some(address),
        Err(_) => {
            problems.push(ConfigProblem::Malformed {
                variable,
                expectation: Expectation::AbsoluteHttpUrl,
            });
            None
        }
    }
}

/// 审计留存：未设 = 永久；否则必须是 ≥ 1 的整数天。
fn parse_audit_retention(env_map: &EnvMap, problems: &mut Vec<ConfigProblem>) -> AuditRetention {
    match parse_retention_days(env::optional(env_map, "AUDIT_RETENTION_DAYS")) {
        Ok(RetentionPolicy::Forever) => AuditRetention::Forever,
        Ok(RetentionPolicy::Days(days)) => AuditRetention::Days(
            NonZeroU32::new(days.get()).expect("domain RetentionDays 已排除 0"),
        ),
        Err(_) => {
            problems.push(ConfigProblem::Malformed {
                variable: "AUDIT_RETENTION_DAYS",
                expectation: Expectation::WholeDaysAtLeastOne,
            });
            // 拒绝而不是强转（上游同此）：把 `"0"` 或 `"1.5"` 悄悄变成某个数字，
            // 是在替审计员回答一个他一定会亲自问的问题。这里的返回值只在
            // 已经要报错的路径上出现，永远不会成为生效配置。
            AuditRetention::Forever
        }
    }
}

/// computer 接入：`COMPUTER_SUPERVISOR_URL` 优先，其次 `AGENT_COMPUTER_URL`，都没有则未挂载。
fn parse_computer(env_map: &EnvMap, problems: &mut Vec<ConfigProblem>) -> Option<ComputerConfig> {
    let has_supervisor = env::optional(env_map, "COMPUTER_SUPERVISOR_URL").is_some();
    let has_shared = env::optional(env_map, "AGENT_COMPUTER_URL").is_some();
    if !has_supervisor && !has_shared {
        return None;
    }

    let allow_private_hosts =
        env::optional(env_map, "AGENT_COMPUTER_ALLOW_PRIVATE_HOSTS") == Some("true");
    let token = env::optional(env_map, "COMPUTER_TOKEN").map(Secret::new);
    // 这一步只在"至少配了一个 computer 地址"之后才走到 —— 上面那个提前 return 就是
    // 上游的形状，理由见 `ComputerConfig::action_policy` 的字段文档。
    let action_policy = match env::optional(env_map, "AGENT_COMPUTER_POLICY") {
        None => None,
        Some(raw) => match parse_action_policy(raw) {
            Ok(policy) => Some(policy),
            Err(expectation) => {
                problems.push(ConfigProblem::Malformed {
                    variable: "AGENT_COMPUTER_POLICY",
                    expectation,
                });
                None
            }
        },
    };

    let provider = if has_supervisor {
        let base_url = parse_optional_address(env_map, "COMPUTER_SUPERVISOR_URL", problems)?;
        ComputerProvider::Docker {
            base_url,
            supervisor_token: env::optional(env_map, "SUPERVISOR_TOKEN").map(Secret::new),
        }
    } else {
        let base_url = parse_optional_address(env_map, "AGENT_COMPUTER_URL", problems)?;
        ComputerProvider::Shared { base_url }
    };

    Some(ComputerConfig {
        provider,
        allow_private_hosts,
        token,
        action_policy,
    })
}

#[cfg(test)]
mod tests {
    use openbot_domain::policy::PolicyMode;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn codes(error: &ConfigError) -> Vec<(&'static str, &'static str)> {
        error
            .problems()
            .iter()
            .map(|problem| (problem.code(), problem.variable()))
            .collect()
    }

    /// 一张空表就能起来，且每个缺省值都是上游实测到的那个。
    ///
    /// 这是全组的正向对照：没有它，一个恒返回 `Err` 的解析器会让下面每条拒绝用例通过。
    #[test]
    fn an_empty_environment_starts_with_the_upstream_defaults() {
        let config = ServerConfig::from_env_map(&EnvMap::new()).expect("空表必须能起来");
        assert_eq!(config.port, 3001);
        assert_eq!(config.tenant_package_directory, "../examples/fintech");
        assert_eq!(
            config.deployment_environment,
            DeploymentEnvironment::Production
        );
        assert_eq!(config.audit_retention, AuditRetention::Forever);
        assert_eq!(config.deployment_id, None);
        assert_eq!(config.public_url, None);
        assert_eq!(config.app_url, None);
        assert_eq!(config.app_dist_dir, None);
        // 没配地址 = 能力未挂载，而不是挂载了但坏着。
        assert_eq!(config.computer, None);
        assert_eq!(config.public_transport(), PublicTransport::Unconfigured);
    }

    /// 缺省即生产；只有显式 `development` 才是开发态；别的一律拒绝。
    #[test]
    fn deployment_environment_defaults_to_production_and_refuses_anything_else() {
        assert_eq!(
            ServerConfig::from_env_map(&env(&[("OPENBOT_ENV", "production")]))
                .expect("合法")
                .deployment_environment,
            DeploymentEnvironment::Production
        );
        // 正向对照：显式开发态确实读得出来，否则本组在"恒 Production"的世界里同样通过。
        assert_eq!(
            ServerConfig::from_env_map(&env(&[("OPENBOT_ENV", "development")]))
                .expect("合法")
                .deployment_environment,
            DeploymentEnvironment::Development
        );

        for bad in ["Production", "prod", "dev", "staging", "PRODUCTION"] {
            let error = ServerConfig::from_env_map(&env(&[("OPENBOT_ENV", bad)]))
                .expect_err("认不出的取值必须拒绝启动");
            assert_eq!(codes(&error), vec![("malformed_env_var", "OPENBOT_ENV")]);
        }
    }

    /// 端口：读得出就用，读不出就拒绝。
    #[test]
    fn port_is_parsed_or_refused() {
        assert_eq!(
            ServerConfig::from_env_map(&env(&[("PORT", "8080")]))
                .expect("合法")
                .port,
            8080
        );
        // `0` 是合法值：内核挑一个空闲端口。
        assert_eq!(
            ServerConfig::from_env_map(&env(&[("PORT", "0")]))
                .expect("合法")
                .port,
            0
        );
        for bad in ["abc", "-1", "70000", "3001abc", "3.14"] {
            let error =
                ServerConfig::from_env_map(&env(&[("PORT", bad)])).expect_err("读不出就该拒绝");
            assert_eq!(codes(&error), vec![("malformed_env_var", "PORT")]);
        }
    }

    /// 留存窗口：未设 = 永久；≥ 1 的整数 = 天数；其余拒绝。
    #[test]
    fn audit_retention_refuses_rather_than_coercing() {
        let days = ServerConfig::from_env_map(&env(&[("AUDIT_RETENTION_DAYS", "365")]))
            .expect("合法")
            .audit_retention;
        assert_eq!(
            days,
            AuditRetention::Days(NonZeroU32::new(365).expect("365"))
        );
        assert_eq!(
            ServerConfig::from_env_map(&env(&[(
                "AUDIT_RETENTION_DAYS",
                "\u{FEFF}\u{3000}365\u{00A0}",
            )]))
            .expect("环境 trim 必须逐字对齐 ECMAScript")
            .audit_retention,
            AuditRetention::Days(NonZeroU32::new(365).expect("365"))
        );

        for bad in [
            "0",
            "-1",
            "1.5",
            "forever",
            "365 days",
            "+7",
            "0x10",
            "0b101",
            "1e3",
            "7.0",
            "\u{0085}365\u{0085}",
        ] {
            let error = ServerConfig::from_env_map(&env(&[("AUDIT_RETENTION_DAYS", bad)]))
                .expect_err("Rust 审计控制只收十进制正整数，不能借上游 Number 强转");
            assert_eq!(
                codes(&error),
                vec![("malformed_env_var", "AUDIT_RETENTION_DAYS")]
            );
        }

        // 空串按未设处理（上游 `optional()` 同此），所以是"永久"而不是"写错了"。
        assert_eq!(
            ServerConfig::from_env_map(&env(&[("AUDIT_RETENTION_DAYS", "")]))
                .expect("空串即未设")
                .audit_retention,
            AuditRetention::Forever
        );
    }

    /// 公共地址：合法就解析，尾斜杠剥掉，非法就拒绝。
    #[test]
    fn public_url_must_be_answerable() {
        let config = ServerConfig::from_env_map(&env(&[(
            "OPENBOT_PUBLIC_URL",
            "https://openbot.example.com/",
        )]))
        .expect("合法");
        let address = config.public_url.as_ref().expect("已设");
        assert_eq!(address.as_str(), "https://openbot.example.com");
        assert_eq!(config.public_transport(), PublicTransport::Https);

        for bad in ["not a URL", "openbot.example.com", "ftp://x.test"] {
            let error = ServerConfig::from_env_map(&env(&[("OPENBOT_PUBLIC_URL", bad)]))
                .expect_err("回答不了 Secure 那个问题的值必须拒绝");
            assert_eq!(
                codes(&error),
                vec![("malformed_env_var", "OPENBOT_PUBLIC_URL")]
            );
        }
    }

    /// `Secure` 的三种情形，从**环境变量**这一端穿到判定 —— 不只是测那个纯函数。
    #[test]
    fn the_cookie_decision_is_reachable_from_the_environment() {
        let cases = [
            (
                "https://openbot.example.com",
                PublicTransport::Https,
                true,
                false,
            ),
            (
                "http://localhost:3001",
                PublicTransport::LoopbackHttp,
                false,
                false,
            ),
            (
                "http://openbot.example.com",
                PublicTransport::PublicHttp,
                false,
                true,
            ),
        ];
        for (raw, expected, secure, insecure) in cases {
            let config =
                ServerConfig::from_env_map(&env(&[("OPENBOT_PUBLIC_URL", raw)])).expect("合法");
            let transport = config.public_transport();
            assert_eq!(transport, expected, "{raw}");
            assert_eq!(transport.cookie_secure(), secure, "{raw}");
            assert_eq!(transport.insecure_transport(), insecure, "{raw}");
        }
    }

    /// App 地址的回落链逐节走一遍。
    #[test]
    fn app_url_falls_back_through_every_link_in_order() {
        // 第一节：显式设了就用它。
        let explicit = ServerConfig::from_env_map(&env(&[
            ("OPENBOT_APP_URL", "http://localhost:3010/"),
            ("TRUSTED_ORIGINS", "http://origin.test"),
            ("OPENBOT_PUBLIC_URL", "https://api.test"),
        ]))
        .expect("合法");
        assert_eq!(explicit.app_url.as_deref(), Some("http://localhost:3010"));

        // 第二节：可信来源的第一项。
        let from_origins = ServerConfig::from_env_map(&env(&[
            (
                "TRUSTED_ORIGINS",
                " http://first.test , http://second.test ",
            ),
            ("OPENBOT_PUBLIC_URL", "https://api.test"),
        ]))
        .expect("合法");
        assert_eq!(from_origins.app_url.as_deref(), Some("http://first.test"));

        // 第三节：公共地址本身 —— 一个 API 与 App 同源的部署就是这一档。
        let from_public =
            ServerConfig::from_env_map(&env(&[("OPENBOT_PUBLIC_URL", "https://api.test")]))
                .expect("合法");
        assert_eq!(from_public.app_url.as_deref(), Some("https://api.test"));

        // 链尾：一节都没有就是 None，而不是某个编出来的缺省。
        assert_eq!(
            ServerConfig::from_env_map(&EnvMap::new())
                .expect("合法")
                .app_url,
            None
        );
    }

    /// supervisor 优先于共享 computer。
    #[test]
    fn supervisor_wins_over_the_shared_computer() {
        let config = ServerConfig::from_env_map(&env(&[
            ("COMPUTER_SUPERVISOR_URL", "http://localhost:4300"),
            ("AGENT_COMPUTER_URL", "http://localhost:4100"),
            ("SUPERVISOR_TOKEN", "supervisor-token"),
            ("COMPUTER_TOKEN", "computer-token"),
        ]))
        .expect("合法");
        let computer = config.computer.as_ref().expect("已挂载");
        match &computer.provider {
            ComputerProvider::Docker {
                base_url,
                supervisor_token,
            } => {
                assert_eq!(base_url.as_str(), "http://localhost:4300");
                assert_eq!(
                    supervisor_token.as_ref().map(Secret::expose),
                    Some("supervisor-token")
                );
            }
            ComputerProvider::Shared { .. } => panic!("设了 supervisor 就该走 Docker"),
        }
        assert_eq!(
            computer.token.as_ref().map(Secret::expose),
            Some("computer-token")
        );

        // 正向对照：只设共享地址时确实走另一支，否则上一条在"恒 Docker"的世界里同样通过。
        let shared =
            ServerConfig::from_env_map(&env(&[("AGENT_COMPUTER_URL", "http://localhost:4100")]))
                .expect("合法");
        assert!(matches!(
            shared.computer.as_ref().expect("已挂载").provider,
            ComputerProvider::Shared { .. }
        ));
    }

    /// 私网开关的判据是字符串恒等 `"true"`，不是布尔解析。
    #[test]
    fn allowing_private_hosts_is_an_exact_string_match() {
        let base = ("AGENT_COMPUTER_URL", "http://localhost:4100");
        let on = ServerConfig::from_env_map(&env(&[
            base,
            ("AGENT_COMPUTER_ALLOW_PRIVATE_HOSTS", "true"),
        ]))
        .expect("合法");
        assert!(on.computer.expect("已挂载").allow_private_hosts);

        // 负向：这些都**不是**"打开"。一个写着 `1` 的部署以为自己关着 —— 它确实关着。
        for not_true in ["1", "TRUE", "yes", "on", "false", ""] {
            let off = ServerConfig::from_env_map(&env(&[
                base,
                ("AGENT_COMPUTER_ALLOW_PRIVATE_HOSTS", not_true),
            ]))
            .expect("合法");
            assert!(
                !off.computer.expect("已挂载").allow_private_hosts,
                "{not_true:?} 不该被当成 true"
            );
        }
    }

    /// 策略在启动期被解析成领域类型，非法即拒绝启动。
    #[test]
    fn the_action_policy_is_parsed_at_start_up() {
        let config = ServerConfig::from_env_map(&env(&[
            ("AGENT_COMPUTER_URL", "http://localhost:4100"),
            (
                "AGENT_COMPUTER_POLICY",
                r#"{"mode":"dry-run","deny":["true"]}"#,
            ),
        ]))
        .expect("合法策略");
        let policy = config
            .computer
            .expect("已挂载")
            .action_policy
            .expect("已配置");
        assert_eq!(policy.mode, PolicyMode::DryRun);
        assert_eq!(policy.deny, vec!["true"]);
        // 没写 allow ⇒ 空表 ⇒ 什么都不放行。**不是**"放行一切"。
        assert!(policy.allow.is_empty());
    }

    /// 非法策略拒绝启动，而不是回落到某个缺省。
    ///
    /// 这条闭合了 `parity/env.yaml::agent-computer-policy`：上游
    /// `config.ts::actionPolicy` 对非法 JSON 与错 shape 都 throw。
    #[test]
    fn a_malformed_action_policy_refuses_to_start() {
        for (raw, expectation) in [
            ("{ this is not json", "action_policy_json"),
            ("[]", "action_policy_object"),
            (r#"{"deny":[]}"#, "action_policy_mode"),
            (r#"{"mode":"audit"}"#, "action_policy_mode"),
            (
                r#"{"mode":"enforce","deny":"true"}"#,
                "action_policy_deny_list",
            ),
            (
                r#"{"mode":"enforce","allow":[1]}"#,
                "action_policy_allow_list",
            ),
        ] {
            let error = ServerConfig::from_env_map(&env(&[
                ("AGENT_COMPUTER_URL", "http://localhost:4100"),
                ("AGENT_COMPUTER_POLICY", raw),
            ]))
            .expect_err("非法策略必须拒绝启动");
            assert_eq!(
                codes(&error),
                vec![("malformed_env_var", "AGENT_COMPUTER_POLICY")],
                "{raw}"
            );
            assert_eq!(
                error.problems()[0],
                ConfigProblem::Malformed {
                    variable: "AGENT_COMPUTER_POLICY",
                    expectation: match expectation {
                        "action_policy_json" => Expectation::ActionPolicyJson,
                        "action_policy_object" => Expectation::ActionPolicyObject,
                        "action_policy_mode" => Expectation::ActionPolicyMode,
                        "action_policy_deny_list" => Expectation::ActionPolicyDenyList,
                        _ => Expectation::ActionPolicyAllowList,
                    },
                },
                "{raw}"
            );
        }
    }

    /// **没配 computer 地址时这个变量根本不被解析** —— 上游实测行为，刻意照搬。
    ///
    /// 这一条反直觉，所以要有测试钉住：否则下一个人会把它当缺陷"顺手修好"，
    /// 从而让一份不会被任何人读到的策略把部署挡在门外。
    #[test]
    fn without_a_computer_address_the_policy_is_never_looked_at() {
        let config =
            ServerConfig::from_env_map(&env(&[("AGENT_COMPUTER_POLICY", "{ this is not json")]))
                .expect("上游在这种环境下照常启动");
        assert_eq!(config.computer, None);

        // 正向对照：同一份坏策略，一旦配上 computer 地址就会被拒 —— 否则本条在
        // "策略永远不被校验"的世界里同样通过。
        assert!(
            ServerConfig::from_env_map(&env(&[
                ("AGENT_COMPUTER_URL", "http://localhost:4100"),
                ("AGENT_COMPUTER_POLICY", "{ this is not json"),
            ]))
            .is_err()
        );
    }

    /// 退役 / 改名变量从 [`ServerConfig::from_env_map`] 这一个入口就能被拦住。
    ///
    /// 判据是"入口本身会报"，而不是"那张表里有这一项"—— 后者在"根本没人调用扫描"
    /// 的世界里同样为真。
    #[test]
    fn migrated_variables_are_refused_at_the_single_entry_point() {
        let error = ServerConfig::from_env_map(&env(&[("INTELLIGENCE_API_URL", "http://x.test")]))
            .expect_err("退役变量必须拦在启动期");
        assert_eq!(
            codes(&error),
            vec![("retired_env_var", "INTELLIGENCE_API_URL")]
        );
    }

    /// 一次启动把配置里所有毛病列全。
    ///
    /// 这条是"错误类型要能同时报告多个问题"那条要求的执行面：五个毛病，一次全出。
    ///
    /// 用例本身就是一份**迁移中途**的配置：旧公共地址变量与新的同时在场
    /// （这正是照着迁移文档改了一半的样子），所以那一条报的是
    /// `renamed_env_var_collision` 而不是 `renamed_env_var` —— 见
    /// [`crate::config::migration`] 模块文档里"旧名与新名同时出现"那一段。
    #[test]
    fn every_problem_in_one_pass() {
        let error = ServerConfig::from_env_map(&env(&[
            ("AGENT_TOOL_TOKEN", "leftover"),
            ("BETTER_AUTH_URL", "http://old.test"),
            ("PORT", "not-a-port"),
            ("AUDIT_RETENTION_DAYS", "0"),
            ("OPENBOT_PUBLIC_URL", "not a url"),
        ]))
        .expect_err("五处毛病");
        assert_eq!(
            codes(&error),
            vec![
                ("retired_env_var", "AGENT_TOOL_TOKEN"),
                ("renamed_env_var_collision", "BETTER_AUTH_URL"),
                ("malformed_env_var", "PORT"),
                ("malformed_env_var", "OPENBOT_PUBLIC_URL"),
                ("malformed_env_var", "AUDIT_RETENTION_DAYS"),
            ]
        );

        // 对照：把新名拿掉，同一条就退回普通的"改名"。两种形态都要能出现，
        // 否则"碰撞"这一档等于把改名那一档吃掉了。
        let only_legacy = ServerConfig::from_env_map(&env(&[
            ("AGENT_TOOL_TOKEN", "leftover"),
            ("BETTER_AUTH_URL", "http://old.test"),
        ]))
        .expect_err("两处毛病");
        assert_eq!(
            codes(&only_legacy),
            vec![
                ("retired_env_var", "AGENT_TOOL_TOKEN"),
                ("renamed_env_var", "BETTER_AUTH_URL"),
            ]
        );
    }

    /// 旧名不会被当作新名偷偷读一遍。
    ///
    /// 这条钉住"本 crate 没有第二个读旧名的读者"：一份只写了旧公共地址变量的配置，
    /// 解析出来的公共地址必须是**空**（同时它会因为改名被拒）。
    #[test]
    fn a_legacy_name_never_silently_supplies_the_new_value() {
        let error = ServerConfig::from_env_map(&env(&[("BETTER_AUTH_URL", "https://old.test")]))
            .expect_err("旧名拒绝启动");
        assert_eq!(codes(&error), vec![("renamed_env_var", "BETTER_AUTH_URL")]);

        // 正向对照：换成新名之后确实读得到，否则本条在"公共地址永远读不出来"
        // 的世界里同样通过。
        let config =
            ServerConfig::from_env_map(&env(&[("OPENBOT_PUBLIC_URL", "https://new.test")]))
                .expect("合法");
        assert_eq!(
            config.public_url.as_ref().map(DeploymentAddress::as_str),
            Some("https://new.test")
        );
    }

    /// 机密不会被 `Debug` 打印出来 —— 真实的泄漏形态是有人 `tracing::debug!("{config:?}")`。
    #[test]
    fn debugging_the_whole_config_leaks_no_secret() {
        let config = ServerConfig::from_env_map(&env(&[
            ("COMPUTER_SUPERVISOR_URL", "http://localhost:4300"),
            ("SUPERVISOR_TOKEN", "supervisor-secret-value"),
            ("COMPUTER_TOKEN", "computer-secret-value"),
        ]))
        .expect("合法");
        let printed = format!("{config:?}");
        assert!(!printed.contains("supervisor-secret-value"), "{printed}");
        assert!(!printed.contains("computer-secret-value"), "{printed}");
        // 正向对照：非机密字段照常可见，否则本条在"Debug 什么都不印"的世界里同样通过。
        assert!(printed.contains("localhost:4300"), "{printed}");
    }
}
