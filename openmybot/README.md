# OpenMyBot

OpenMyBot is the local foreground product assembled from the shared OpenBot engine. Wrok Bot and OpenMyBot are maintained in the same workspace with separate product entry points.

The current command surface is `openmybot init --pg-bin-dir <absolute-directory>`, `openmybot daemon`, and `openmybot status`. All three accept `--data-dir <absolute-directory>` and `--json`. Data directory selection uses that argument, then `OPENMYBOT_DATA_DIR`, then `$HOME/Library/Application Support/OpenMyBot`.

Provide PostgreSQL 17 binaries, including `postgres` and `initdb`, in the explicit binary directory. Building the shared server dependencies also requires xmlsec1, libxml2 and OpenSSL. Initialization creates an independent private PostgreSQL cluster and random local keys. The daemon runs in the foreground, supervises that cluster, and exposes a Unix socket protected by the current user's identity and a token rotated at every start. Stop it with SIGINT or SIGTERM.

Status reports process, PostgreSQL, version, deployment and authentication-failure facts. Model execution, channels, host drivers and MCP are pending; the embedded composition package does not establish model availability. No background launch service is installed.

See [中文说明](README.zh-CN.md), [compatibility evidence](compat/README.md), and [host projections](hosts/README.md). This development surface has not completed product release validation.
