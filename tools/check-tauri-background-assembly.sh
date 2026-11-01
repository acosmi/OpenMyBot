#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail() {
  echo "Tauri background assembly guard: $*" >&2
  exit 1
}

source=$(awk '/^mod tests \{/{exit} {print}' crates/openbot-desktop/src/tauri_background.rs)

[[ $(rg -c '^[[:space:]]*\.app_data_dir\(\)' <<<"$source") == 1 ]] \
  || fail "setup must resolve exactly one Tauri app_data_dir authority"
[[ $(rg -c 'PostgresSidecarSupervisor::start\(' <<<"$source") == 1 ]] \
  || fail "verified PostgreSQL sidecar start owner count drift"
[[ $(rg -c 'assemble_postgres_application\(' <<<"$source") == 1 ]] \
  || fail "shared ApplicationService assembly consumer count drift"
[[ $(rg -c 'create_verified_window\(' <<<"$source") == 1 ]] \
  || fail "verified first-window creation count drift"
[[ $(rg -c 'window\.create' <<<"$source") == 1 ]] \
  || fail "external static-window rejection disappeared"
[[ $(rg -c 'DesktopUiPreferenceStore::new\(' <<<"$source") == 1 ]] \
  || fail "Desktop app-data preference adapter count drift"
[[ $(rg -c 'start_desktop_agent_host\(' <<<"$source") == 1 ]] \
  || fail "Desktop Agent host start count drift"
[[ $(rg -c 'PostgresUiPreferenceAdministration::new\(' <<<"$source") == 1 ]] \
  || fail "Desktop PostgreSQL preference authority count drift"

for forbidden in 'std::env' 'server-sso' 'axum::' 'TcpListener' 'ServerBuilder'; do
  if rg -n "$forbidden" <<<"$source" >/dev/null; then
    fail "background owner gained forbidden dependency: $forbidden"
  fi
done

line_of() {
  local pattern="$1"
  rg -n "$pattern" crates/openbot-desktop/src/tauri_background.rs \
    | head -1 | cut -d: -f1
}

prepared_line=$(line_of 'prepare_desktop_local_runtime\(app_data_root, config\)\.await')
slot_line=$(line_of 'setup_slot\.install')
owner_line=$(line_of '\.install_owner\(&mut owner, Arc::clone\(&lifecycle\)\)')
window_line=$(line_of 'let window = lifecycle\.create_verified_window')
[[ $prepared_line -lt $slot_line && $slot_line -lt $owner_line && $owner_line -lt $window_line ]] \
  || fail "prepare→protocol→owner→window order drift"

python3 tools/tauri_background_assembly_guard.py \
  crates/openbot-desktop/src/tauri_background.rs \
  || fail "production Desktop Local staged shutdown structure drift"

grep -Fq 'desktop-local-runtime = [' crates/openbot-desktop/Cargo.toml \
  || fail "desktop-local-runtime feature missing"
grep -Fq '    "openbot-infra/server-runtime",' crates/openbot-desktop/Cargo.toml \
  || fail "full Desktop runtime lost shared Infra adapters"
grep -Fq '    "dep:openbot-agent",' crates/openbot-desktop/Cargo.toml \
  || fail "full Desktop runtime lost built-in Agent host"
if rg -n 'openbot-infra/server-sso' crates/openbot-desktop/Cargo.toml >/dev/null; then
  fail "Desktop runtime pulled Server SSO/xmlsec"
fi

[[ $(rg -c 'ui_preferences: Arc<dyn UiPreferenceAdministration>' crates/openbot-infra/src/application_assembly.rs) == 1 ]] \
  || fail "shared assembly host preference port missing"
[[ $(rg -c 'ui_preferences: Arc::new\(PostgresUiPreferenceAdministration::new' crates/openbot-server/src/main.rs) == 1 ]] \
  || fail "Server must inject its PostgreSQL preference adapter once"

agent_source=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' crates/openbot-desktop/src/desktop_agent_runtime.rs)
[[ $(rg -c 'RunRelay::start_with_database\(' <<<"$agent_source") == 1 ]] \
  || fail "Desktop durable RunRelay count drift"
[[ $(rg -c 'BuiltInAgentRuntime::start_with_remote_interrupts\(' <<<"$agent_source") == 1 ]] \
  || fail "Desktop built-in Agent + durable interrupt runtime count drift"
[[ $(rg -c 'SafeRemoteAguiTransport::new\(' <<<"$agent_source") == 1 ]] \
  || fail "Desktop remote Agent transport is no longer the concrete SafeDialer adapter"
if rg -n 'std::env|allow_http|environment_api_key|SchemePolicy::HttpOrHttps' <<<"$agent_source" >/dev/null; then
  fail "Desktop Agent host gained environment or plaintext HTTP fallback"
fi

slot_source=$(awk '/^mod tests \{/{exit} {print}' crates/openbot-desktop/src/tauri_host.rs)
[[ $(rg -c 'empty_response\(StatusCode::SERVICE_UNAVAILABLE\)' <<<"$slot_source") == 1 ]] \
  || fail "pending custom protocol no longer returns fail-closed 503"
[[ $(rg -c 'ProtocolAlreadyReady' <<<"$slot_source") -ge 3 ]] \
  || fail "protocol slot no longer rejects replacement"

echo "Tauri background assembly guard: ok (app_data=1; sidecar=1; shared-app=1; Agent+relay=1; window-last=1; local-prefs=1; concurrent staged shutdown; SSO=0)"
