# Host projections

`crabcode/` holds the CrabCode projection: a plugin manifest that starts `openmybot mcp` as a stdio MCP server, and one skill that describes its five tools.

Requirements: the `openmybot` binary is on the `PATH` of the host process; the daemon runs under the same user with the same data directory (set `OPENMYBOT_DATA_DIR` in the host's environment when it is not the default one); the owner has bound the host with `openmybot bindings host crabcode --workspace <absolute-directory>`. The server speaks two MCP protocol revisions and no other: 2025-11-25, negotiated through `initialize`, and 2026-07-28, which starts with `server/discover`. A host whose MCP client negotiates neither cannot use it.

The projection has been checked offline only, with the host's plugin validation: run `crabcode plugin validate openmybot/hosts/crabcode` from the repository root. Loading it in a host release is not covered by the [compatibility evidence](../compat/README.md).

See the [OpenMyBot entry point](../README.md).
