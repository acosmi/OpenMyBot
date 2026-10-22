<p align="center">
  <img src=".github/assets/wrok-bot-banner.png" alt="Wrok Bot" width="100%">
</p>

<h1 align="center">Wrok Bot</h1>

<p align="center">
  <b>AI 员工 / 数字队友平台 · 能独立干活的 AI 同事</b><br>
  基于 Rust 构建 · 首版面向 macOS · 开发验证中
</p>

<p align="center">
  <a href="#源码目录"><img src="https://img.shields.io/badge/core-Rust-007ec6?style=flat-square" alt="Core: Rust"></a>
  <a href="crates/openbot-desktop/Cargo.toml"><img src="https://img.shields.io/badge/desktop-Tauri-00897b?style=flat-square" alt="Desktop: Tauri"></a>
  <a href="crates/openbot-infra/src/db"><img src="https://img.shields.io/badge/data-PostgreSQL-149954?style=flat-square" alt="Data: PostgreSQL"></a>
  <a href="#当前进度"><img src="https://img.shields.io/badge/status-In%20development-68448b?style=flat-square" alt="Status: in development"></a>
  <br>
  <a href="IMPLEMENTATION_LEDGER.md"><img src="https://img.shields.io/badge/evidence-implementation%20ledger-e65100?style=flat-square" alt="Implementation ledger"></a>
  <a href="https://wrokbot.com"><img src="https://img.shields.io/badge/main%20site-wrokbot.com-0052d9?style=flat-square" alt="Official website: wrokbot.com (primary)"></a>
  <a href="https://grokbot.si"><img src="https://img.shields.io/badge/website-grokbot.si-00897b?style=flat-square" alt="Official website: grokbot.si"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Custom-4c6ef5?style=flat-square" alt="License terms"></a>
</p>

<p align="center"><a href="README.md">English</a> | <strong>简体中文</strong></p>

Wrok Bot 是一个使用 Rust 构建的 AI 员工 / 数字队友平台，定位为“能独立干活的 AI 同事”。平台包含桌面宿主、服务端、Web 界面和开发中的移动客户端。项目目前处于开发验证阶段，首版优先面向 macOS。

官方网站：[wrokbot.com](https://wrokbot.com)（主域名）· [grokbot.si](https://grokbot.si)。

## 当前进度

状态更新：2026-10-16。以下依据当前 v7 基线与已发布主线；分项测试通过不代表安装包或完整产品已经验收。

| 模块 | 当前情况 | 首版仍需完成 |
| --- | --- | --- |
| 工作台与界面 | 品牌、频道、同事、技能、记忆、管理及会话界面已有实现；已有定向 UI 测试和 Web 构建验证。已合并的浏览器旅程覆盖未设置语言时跟随系统语言、所有者离开时取消名册读取，以及语言变更后刷新未知事实 | macOS 实际窗口的完整操作、键盘与可访问性验收；参考像素、原生窗口和生产验收仍开放 |
| 本机服务与数据 | 本地服务、PostgreSQL、会话与数据持久化已有分项验证。经授权可停止一条线程历史；其后在该已关闭历史上的上下文读取、自定义启动、工具效果、显式保存和带来源记忆均被拒绝。该历史上的在途运行由系统动作排空。本机 macOS 宿主已有停止窗口及相关时限用例的定向检查。已实现已关闭历史持久副本的有界清除、完成后读取不可见，以及已删除线程的维护 CLI；已有定向证据保留其对应的已合入候选归属 | 完整 GUI 历史停止／清除入口、干净安装、凭据访问、稳定启动退出、升级与完整恢复。清除之后的恢复及完整签名产品验收仍待完成 |
| 模型接入 | 自定义连接管理、持久化的自定义目录，以及当前库自定义 v2 的接受、快照、上下文和启动已有有限实现；共享推理已有实现。SDK 授权、注册和分发已有有限交付；网关传输仍待组合验收 | 网关、账户桥接、自定义模型的选择、真实对话、工具、取消和恢复闭环。这三项来源的就绪状态尚未建立 |
| 系统确认与授权 | 本机确认状态机、窗口生命周期及相关测试已有实现 | 正式签名 App 上的原生认证、取消、锁屏和睡眠验证 |
| 浏览器与电脑操作 | Engine、画面传输、控制权限与输入已有分项实现 | 产品内真实操作、人工接管、停止和故障恢复的完整验证 |
| 移动客户端 | 共享页面源码和本地 Web 预览可用，已有 iOS/Android 资源编译记录 | 真实账户、设备绑定、原生安装及各平台真机验收；不计入 macOS 首版完成范围 |

## 发布条件

**当前交付目标：macOS 首版，发布验收尚未完成。** 先前九月的估算不构成已经验证的交付承诺；新的日期须以剩余产品流程和签名安装包的验收证据为依据。

首版目标是可安装的 macOS 产品，完成工作台与 AI 工具、浏览器操作与接管、原生电脑操作与停止三类核心使用流程，并验证模型接入、凭据保护、数据恢复和安装启动。

当前首版尚未完成。线程历史的关闭、排空和有界清除，并不完成安装、凭据保护、恢复或签名应用验收。发布前仍需通过真实签名安装包、实际模型服务和 macOS 真机的组合验收。Apple Silicon 与 Intel 的支持范围以实际验证结果为准。Windows、Linux 和移动端后续分别验证并公布进展。

## 源码目录

- `crates/`：领域、应用、基础设施、桌面、服务端、UI 和测试工具。
- `apps/wrok-bot-mobile/`：移动客户端源码。
- `examples/`：示例应用配置。
- `fixtures/`：确定性测试数据和资源契约。
- `tools/`：依赖检查与构建工具版本配置。

Rust 工具链由 `rust-toolchain.toml` 固定，Rust 依赖由 `Cargo.lock` 锁定。原生库要求因平台而异；CI 工作流记录 Linux 构建依赖，`.cargo/config.toml` 配置 macOS 库搜索路径。

## 服务端传输

服务端监听 `127.0.0.1`，本机单用户运行使用 `--local`。远程部署必须使用同机 TLS 反向代理，配置 HTTPS `WROK_BOT_PUBLIC_URL`，以及包含 64 位小写十六进制字符的 `WROK_BOT_TLS_PROXY_SECRET`；原 `OPENBOT_*` 变量名仍兼容。

代理须丢弃客户端传入的 `x-wrok-bot-proxy-secret`、`x-forwarded-proto`、`x-forwarded-host`，分别重新设置唯一的共享秘密、`https` 和公共 URL 的精确 authority（含显式配置的端口），且只转发实际通过 HTTPS 到达的请求。秘密仅保存在代理与后端，不得放进浏览器代码或客户端请求。仅声明公共 URL 不构成请求授权。未经核验的请求只能读取健康诊断，readiness 返回 503，登录与业务路由不可用。服务端本身不提供直接 TLS listener。

### MCP 凭据撤销与恢复

断开 MCP 连接先让本地凭据失效，厂商侧撤销可能仍待完成。须保留撤销记录，服务才能按原服务器及凭据上下文继续补偿。出现 `operator_required` 时，应在厂商管理界面撤销对应凭据并核实结果，再重新连接。不得删除撤销记录、重建同名服务器替换原身份，或恢复旧凭据来消除报错。

处于 pending 或 unknown 的 OAuth 刷新操作同样会阻止旧凭据复用，不会因超时或配置回退自动清除。须显式重连取得新凭据，旧操作仍保留供查证；若厂商可能继续接受旧凭据，也应在厂商侧撤销。本地断开或重连成功，不代表厂商撤销已经完成。

## 本地检查

```sh
cargo fmt --all -- --check
cargo test -p openbot-testkit --features xtask --bin xtask
cargo xtask parity-check --fixtures-only
cargo xtask recount --fixtures-only
cargo xtask i18n-check
cargo xtask design-lint
```

两条 `--fixtures-only` 命令只检查公开 fixture 台账及其六项登记计数。复算由固定的 Rust YAML 解析器执行精确已知查询，不需要 Python 或 PyYAML；结果不代表迁移 parity、overlay 或产品准入通过。省略该参数时必须提供九份迁移账本、overlay 和 fixture 台账，缺一即失败；完整复算还可通过 `--require-upstream` 要求固定上游检出。

提交前安装本地发布检查，需要 Python 3 和 Gitleaks：

```sh
python3 tools/repository_guard.py install
```

检查会在提交前检查暂存内容，在推送前检查待发布的完整历史。GitHub Actions 保持手动触发。

## 许可与声明

本项目第一方代码个人免费使用，企业使用需取得授权，具体条款见 [LICENSE](LICENSE)。

项目参考 grok bot 与 open bot，并结合开源项目 crabcode-tui 进行产品与技术规划。第三方声明见 [NOTICE](NOTICE)，相关代码、字体、图标等资源保留各自许可证。
