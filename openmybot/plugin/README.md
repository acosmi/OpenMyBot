# OpenMyBot host package

This directory is an Agent Plugins 1.0.0 package: a root `plugin.json`, an `mcp.json` that starts `openmybot mcp` as a stdio MCP server, and one skill under `skills/` that describes its five tools. The same directory keeps `.crabcode-plugin/` for CrabCode and `.claude-plugin/` for Claude Code; each host reads its own manifest, so install the package once per machine. The Claude Code manifest starts `openmybot mcp --host claude`, so its calls use the Claude Code host binding; the other manifests start `openmybot mcp`, which uses the CrabCode host binding.

Requirements: the `openmybot` binary is on the `PATH` of the host process; the daemon runs under the same user with the same data directory (set `OPENMYBOT_DATA_DIR` in the host's environment when it is not the default one); the owner has bound the host with `openmybot bindings host <host> --workspace <absolute-directory>`, where `<host>` is `crabcode` or `claude`. The server speaks two MCP protocol revisions and no other: 2025-11-25, negotiated through `initialize`, and 2026-07-28, which starts with `server/discover`. A host whose MCP client negotiates neither cannot use it.

The projection has been checked offline only, with the host's plugin validation: run `crabcode plugin validate openmybot/plugin` from the repository root. Loading it in a host release is not covered by the [compatibility evidence](../compat/README.md). The root `plugin.json` and `mcp.json` are checked against the published 1.0.0 schemas during review, not by `crabcode plugin validate`, which reads only `.crabcode-plugin/`.

Hosts other than CrabCode, Claude Code included, are not covered until a record exists under `../compat/` (see the [compatibility evidence](../compat/README.md)).

See the [OpenMyBot entry point](../README.md).
