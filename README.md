<p align="center">
  <img src=".github/assets/wrok-bot-banner.png" alt="Wrok Bot" width="100%">
</p>

<h1 align="center">Wrok Bot</h1>

<p align="center">
  <b>AI employee / digital teammate platform · AI coworkers who can work independently</b><br>
  Built with Rust · macOS first · In development
</p>

<p align="center">
  <a href="#source-layout"><img src="https://img.shields.io/badge/core-Rust-007ec6?style=flat-square" alt="Core: Rust"></a>
  <a href="crates/openbot-desktop/Cargo.toml"><img src="https://img.shields.io/badge/desktop-Tauri-00897b?style=flat-square" alt="Desktop: Tauri"></a>
  <a href="crates/openbot-infra/src/db"><img src="https://img.shields.io/badge/data-PostgreSQL-149954?style=flat-square" alt="Data: PostgreSQL"></a>
  <a href="#current-progress"><img src="https://img.shields.io/badge/status-In%20development-68448b?style=flat-square" alt="Status: in development"></a>
  <br>
  <a href="IMPLEMENTATION_LEDGER.md"><img src="https://img.shields.io/badge/evidence-implementation%20ledger-e65100?style=flat-square" alt="Implementation ledger"></a>
  <a href="https://wrokbot.com"><img src="https://img.shields.io/badge/main%20site-wrokbot.com-0052d9?style=flat-square" alt="Official website: wrokbot.com (primary)"></a>
  <a href="https://grokbot.si"><img src="https://img.shields.io/badge/website-grokbot.si-00897b?style=flat-square" alt="Official website: grokbot.si"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Custom-4c6ef5?style=flat-square" alt="License terms"></a>
</p>

<p align="center"><strong>English</strong> | <a href="README.zh-CN.md">简体中文</a></p>

Wrok Bot is an AI employee / digital teammate platform built with Rust, designed to provide AI coworkers who can get work done independently. The platform includes a desktop host, server, web interface, and a mobile client under development. The project is currently in development and validation, with macOS as the first release platform.

Official websites: [wrokbot.com](https://wrokbot.com) (primary) · [grokbot.si](https://grokbot.si).

## Current progress

Status as of October 16, 2026, based on the current v7 baseline and the published main line. Passing individual checks does not mean the installer or the complete product has passed release validation.

| Module | Current status | Remaining work for the first release |
| --- | --- | --- |
| Workbench and UI | Branding, channels, coworkers, skills, memory, administration, and conversation screens are implemented. Directed UI tests and web builds have been validated. Merged browser journeys cover system-language fallback when locale is unset, cancelling roster reads when their owner leaves, and refreshing unknown facts after a language change | Complete workflow, keyboard, and accessibility validation in actual macOS windows. Reference pixels, native windows, and production acceptance remain open |
| Local services and data | Local services, PostgreSQL, sessions, and persistence have passed individual checks. An authorized close can stop one thread history. Later context reads, custom starts, tool effects, explicit saves, and sourced memory on that closed history are refused. In-flight runs on the closed history are drained by a system action. Directed macOS host checks cover the local stop window and the related deadline cases. Bounded clearing of persisted closed-history copies, completion-gated reader visibility, and a maintenance CLI for deleted threads are also implemented, with directed evidence tied to the merged candidates | Complete GUI history stop/clear controls, clean installation, credential access, reliable startup and shutdown, upgrades, and full recovery. Recovery after clearing and complete signed-product validation remain open |
| Model connections | Custom connection management, a persisted custom catalog, and a limited current-library custom v2 path for accept, snapshot, context, and start are implemented. Shared inference is implemented. SDK authorization, registration, and dispatch have limited delivered pieces; gateway transport still awaits integration validation | End-to-end model selection, live conversations, tools, cancellation, and recovery across the gateway, account bridge, and custom model connections. Readiness across those three sources is not established |
| System confirmation and authorization | The local confirmation state machine, window lifecycle handling, and related tests are implemented | Native authentication, cancellation, screen locking, and sleep validation in a properly signed app |
| Browser and computer interaction | Engine, screen transport, control permissions, and input have individual implementations | End-to-end validation of real operations, manual takeover, stopping, and failure recovery within the product |
| Mobile client | Shared page source and local web previews are available, with iOS/Android resource compilation records | Real accounts, device binding, native installation, and testing on physical devices for each platform; outside the macOS first-release scope |

## Release readiness

**Current delivery target: the first macOS release; release validation remains incomplete.** The earlier September estimate is not a verified delivery commitment. A new date will require evidence from the remaining product workflows and signed installer validation.

The first release aims to provide an installable macOS product covering three core workflows: the workbench and AI tools, browser interaction with manual takeover, and native computer interaction with stopping controls. Model connections, credential protection, data recovery, installation, and startup must also be validated.

The first release is not yet complete. Closing, draining, and bounded clearing of thread history do not finish installation, credential protection, recovery, or signed-app validation. Release validation still requires a signed installer, live model services, and testing on physical Macs. Apple Silicon and Intel support will be stated according to actual validation results. Windows, Linux, and mobile platforms will be validated separately, with progress published as work advances.

## Source layout

- `crates/`: domain, application, infrastructure, desktop, server, UI, and test tools.
- `apps/wrok-bot-mobile/`: mobile client source.
- `examples/`: sample application configuration.
- `fixtures/`: deterministic test data and asset contracts.
- `tools/`: dependency checks and build tool version configuration.

The Rust toolchain is pinned in `rust-toolchain.toml`, and Rust dependencies are locked in `Cargo.lock`. Native library requirements vary by platform. The CI workflow records Linux build dependencies, while `.cargo/config.toml` configures macOS library search paths.

## Server transport

The server listens on `127.0.0.1`. Local single-user operation uses `--local`. Remote deployments require a TLS reverse proxy on the same machine, an HTTPS `WROK_BOT_PUBLIC_URL`, and `WROK_BOT_TLS_PROXY_SECRET` containing 64 lowercase hexadecimal characters. The original `OPENBOT_*` variable names remain supported.

The proxy must discard incoming `x-wrok-bot-proxy-secret`, `x-forwarded-proto`, and `x-forwarded-host` values, then set exactly one of each: the shared secret, `https`, and the exact authority from the public URL (including an explicitly configured port). Forward only requests that arrived over HTTPS. Keep the secret private to the proxy and backend; never put it in browser code or client requests. A public URL alone does not authorize a request. Unverified requests receive only health diagnostics, with readiness returning 503; authentication and business routes remain unavailable. The server does not provide a direct TLS listener.

### MCP credential revocation recovery

Disconnecting an MCP connection invalidates its local credentials first. Vendor revocation may still be pending; keep the retained revocation record so the service can retry with the original server and credential context. An `operator_required` result requires revoking the credential in the vendor's own administration interface and checking the outcome there before reconnecting. Do not delete revocation records, recreate a same-name server to replace their identity, or restore old credentials to make an error disappear.

A pending or unknown OAuth refresh operation also blocks reuse of that credential. It is not cleared by a timeout or a configuration rollback. Reconnect explicitly to obtain a new credential; the old operation remains available for reconciliation. If the vendor may still accept the old credential, revoke it there as well. A successful local disconnect or reconnect does not prove that vendor revocation completed.

## Local checks

```sh
cargo fmt --all -- --check
cargo test -p openbot-testkit --features xtask --bin xtask
cargo xtask parity-check --fixtures-only
cargo xtask recount --fixtures-only
cargo xtask i18n-check
cargo xtask design-lint
```

The two `--fixtures-only` checks validate the public fixture manifest and its six declared queries. Recount uses the pinned Rust YAML parser for those exact queries; it does not require Python or PyYAML. They do not validate migration parity, overlay closure, or product readiness. Omitting `--fixtures-only` requires all nine migration ledgers, the overlay and fixture manifest, and fails when any required input is absent. Full recount can also require the fixed upstream checkout with `--require-upstream`.

Before committing, install the local publication checks. Python 3 and Gitleaks are required:

```sh
python3 tools/repository_guard.py install
```

The guard checks staged content before commits and the complete history being published before pushes. GitHub Actions remains manually triggered.

## License and acknowledgements

First-party code is free for personal use. Enterprise use requires authorization; see [LICENSE](LICENSE) for the terms.

Product and technical planning draws on grok bot and open bot, together with the open-source project crabcode-tui. See [NOTICE](NOTICE) for third-party acknowledgements. Third-party code, fonts, icons, and other assets retain their respective licenses.
