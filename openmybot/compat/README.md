# Compatibility evidence

This directory is reserved for version-specific compatibility evidence as integrations are delivered. The accepted CrabCode versions are listed in [`crabcode/accepted.json`](crabcode/accepted.json): 1.1.27, recorded in [`crabcode/1.1.27.md`](crabcode/1.1.27.md). CrabCode 1.1.16 is no longer accepted; its recheck record [`crabcode/1.1.16.md`](crabcode/1.1.16.md) is kept as history, and 1.1.16 must pass the gates again before it re-enters the window. There are no accepted channel version claims, Feishu included; the real-channel recheck is pending with the owner. The Feishu long-connection wire protocol this project implements is recorded in [`feishu/long-connection.md`](feishu/long-connection.md); that record is not a version claim. The local daemon does not establish channel, model or MCP compatibility. The host package under [openmybot/plugin](../plugin/README.md) is validated offline for CrabCode only.

## Grok Bot

Grok Bot reads Agent Plugins packages; no compatibility is claimed until the owner records a real-machine check in `grokbot/<version>.md` with the same layout as the CrabCode records. The gates are: G1 the package directory is accepted by the host's plugin install; G2 the stdio server from `mcp.json` is started and `openmybot mcp` negotiates 2026-07-28 or 2025-11-25; G3 the five `wrok_*` tools are listed; G4 the `openmybot` skill is loaded; G5 the host registers the server once even though `.crabcode-plugin/` is also present.

See the [OpenMyBot entry point](../README.md) for the currently available commands.
