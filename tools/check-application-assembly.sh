#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail() {
  echo "Application assembly guard: $*" >&2
  exit 1
}

owners=$(python3 -B tools/application_assembly_guard.py)
# 测试夹具：下列 desktop 文件只经 #[cfg(all(test, feature = "desktop-local-runtime", …))] 模块编入，
# application_assembly_guard.py 只把精确的 #[cfg(test)] 识别为测试模块。
expected_owners=(
  crates/openbot-desktop/src/tauri_host/approval_preference_local_tests.rs # 测试夹具 PR #147
  crates/openbot-desktop/src/tauri_host/artifact_save_receipt_tests.rs # 测试夹具 PR #141
  crates/openbot-desktop/src/tauri_host/artifact_source_run_local_tests.rs # 测试夹具 PR #137
  crates/openbot-desktop/src/tauri_host/current_request_binding_local_tests.rs # 测试夹具 PR #123
  crates/openbot-desktop/src/tauri_host/thread_history_management_local_tests.rs # 测试夹具 PR #181
  crates/openbot-desktop/src/tauri_host/thread_history_stop_clear_local_tests.rs # 测试夹具 PR #204
  crates/openbot-infra/src/application_assembly.rs
)
[[ "$owners" == "$(printf '%s\n' "${expected_owners[@]}")" ]] || \
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
