# OpenMyBot

OpenMyBot is the local foreground product assembled from the shared OpenBot engine. Wrok Bot and OpenMyBot are maintained in the same workspace with separate product entry points.

The current command surface is `openmybot init --pg-bin-dir <absolute-directory>`, `openmybot daemon`, `openmybot status [--run <run-id>]`, `openmybot pair <telegram|feishu> --workspace <absolute-directory> [--run-deadline <seconds>]`, `openmybot bindings list`, `openmybot bindings revoke <binding-id>`, `openmybot bindings reconfirm <binding-id>`, `openmybot bindings reset-thread <binding-id> --ack-unknown <run-id>`, `openmybot bindings receiver telegram` and `openmybot bindings receiver feishu --app-id <app-id>` (both read the secret from the first line of standard input), `openmybot bindings host crabcode --workspace <absolute-directory> [--run-deadline <seconds>]`, `openmybot approve <permission-id>`, `openmybot deny <permission-id>` and `openmybot cancel <run-id>`. Every command accepts `--data-dir <absolute-directory>` and `--json`. Data directory selection uses that argument, then `OPENMYBOT_DATA_DIR`, then `$HOME/Library/Application Support/OpenMyBot`.

Provide PostgreSQL 17 binaries, including `postgres` and `initdb`, in the explicit binary directory. Building the shared server dependencies also requires xmlsec1, libxml2 and OpenSSL. Initialization creates an independent private PostgreSQL cluster and random local keys. The daemon runs in the foreground, supervises that cluster, and exposes a Unix socket protected by the current user's identity and a token rotated at every start. Stop it with SIGINT or SIGTERM.

Status reports process, PostgreSQL, version, deployment and authentication-failure facts and a channel segment. The Telegram receiver, the dispatcher, outcome delivery and the CrabCode host driver are delivered; the Feishu receiver and MCP are pending. The embedded composition package does not establish model availability. No background launch service is installed.

See [中文说明](README.zh-CN.md), [compatibility evidence](compat/README.md), and [host projections](hosts/README.md). This development surface has not completed product release validation.
