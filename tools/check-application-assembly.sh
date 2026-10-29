#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail() {
  echo "Application assembly guard: $*" >&2
  exit 1
}

owners=$(python3 -B tools/application_assembly_guard.py)
[[ "$owners" == "crates/openbot-infra/src/application_assembly.rs" ]] || \
  fail "production OpenBotApplication constructor owners drift: ${owners:-none}"

[[ $(rg -c 'assemble_postgres_application\(' crates/openbot-server/src/main.rs) == 1 ]] || \
  fail "Server must consume shared assembly exactly once"
[[ $(rg -c 'Arc<dyn ApplicationService> = Arc::new\(application\)' crates/openbot-infra/src/application_assembly.rs) == 1 ]] || \
  fail "shared typed application boundary count drift"

source=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' crates/openbot-infra/src/application_assembly.rs)
if rg -n 'std::env|axum::|tauri::|Webview|TcpListener|ServerBuilder' <<<"$source" >/dev/null; then
  fail "shared assembly gained environment or transport/window ownership"
fi
if rg -n 'KEY_ENCRYPTION_KEY|DATABASE_URL|OPENBOT_' <<<"$source" >/dev/null; then
  fail "shared assembly gained process configuration fallback"
fi

listener_source=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' crates/openbot-infra/src/thread_listener.rs)
if rg -n 'std::env|axum::|tauri::|Webview|TcpListener|ServerBuilder|String::|: *String|Vec<String>|Option<String>' \
  <<<"$listener_source" >/dev/null; then
  fail "shared listener config gained transport/window ownership or String secret storage"
fi
[[ $(rg -c 'ThreadListenerDatabase::desktop_local\(' \
  crates/openbot-desktop/src/desktop_local_bootstrap.rs) == 1 ]] || \
  fail "Desktop data plane must mint one listener config from the owned sidecar"
if rg -n 'DatabaseConfig|to_pg_config' \
  crates/openbot-desktop/src/desktop_local_bootstrap.rs >/dev/null; then
  fail "Desktop must not reconstruct the Server database config"
fi

echo "Application assembly guard: ok (one OpenBotApplication owner; Server consumer=1; Desktop listener=1; env/Axum/Tauri/String-secret=0)"
