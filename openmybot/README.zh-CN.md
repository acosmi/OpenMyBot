# OpenMyBot

OpenMyBot 是基于共享 OpenBot 引擎装配的本地前台产品。Wrok Bot 与 OpenMyBot 在同一工作区维护，分别提供产品入口。

当前命令为 `openmybot init --pg-bin-dir <绝对目录>`、`openmybot daemon`、`openmybot status [--run <run-id>]`、`openmybot pair <telegram|feishu> --workspace <绝对目录> [--run-deadline <秒>]`、`openmybot bindings list`、`openmybot bindings revoke <binding-id>`、`openmybot bindings reconfirm <binding-id>`、`openmybot bindings reset-thread <binding-id> --ack-unknown <run-id>`、`openmybot bindings receiver telegram` 与 `openmybot bindings receiver feishu --app-id <app-id>`（二者从标准输入首行读取密钥）、`openmybot bindings host crabcode --workspace <绝对目录> [--run-deadline <秒>]`、`openmybot approve <permission-id>`、`openmybot deny <permission-id>` 和 `openmybot cancel <run-id>`。所有命令均接受 `--data-dir <绝对目录>` 与 `--json`。数据目录依次取显式参数、`OPENMYBOT_DATA_DIR`、`$HOME/Library/Application Support/OpenMyBot`。

请在显式二进制目录中提供 PostgreSQL 17 的 `postgres` 和 `initdb`。构建共享服务端依赖还需要 xmlsec1、libxml2 与 OpenSSL。初始化创建独立私有 PostgreSQL 集群和随机本地密钥。守护进程以前台方式监管该集群，通过当前用户身份及每次启动轮换的 token 保护 Unix socket。使用 SIGINT 或 SIGTERM 停止。

总览报告进程、PostgreSQL、版本、部署、认证失败计数与渠道段。Telegram 接收器、派发器、成果外发与 CrabCode 宿主驱动已交付；飞书接收器与 MCP 尚待交付。嵌入的装配包不代表模型可用。不会安装后台启动服务。

另见 [English](README.md)、[兼容性证据](compat/README.md) 与 [宿主投影](hosts/README.md)。该开发入口尚未完成产品发布验收。
