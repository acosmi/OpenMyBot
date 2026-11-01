#!/usr/bin/env bash
# G6 / Batch 16: exact Tauri release-target, build-script, binary and policy-blocker guard.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  printf 'Tauri dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

cargo_cache_root="${CARGO_HOME:-$HOME/.cargo}"
registry_root="$cargo_cache_root/registry/src"
shopt -s nullglob

crate_root() {
  local package_spec="$1"
  local candidates=("$registry_root"/*/"$package_spec")
  [[ ${#candidates[@]} -eq 1 && -d "${candidates[0]}" ]] \
    || fail "registry source for $package_spec is missing or ambiguous"
  printf '%s' "${candidates[0]}"
}

check_hash() {
  local package_spec="$1"
  local relative_path="$2"
  local expected_hash="$3"
  local source_file
  source_file="$(crate_root "$package_spec")/$relative_path"
  [[ -f "$source_file" ]] || fail "$package_spec/$relative_path is missing"
  local actual_hash
  actual_hash="$(shasum -a 256 "$source_file" | awk '{print $1}')"
  [[ "$actual_hash" == "$expected_hash" ]] \
    || fail "$package_spec/$relative_path hash changed: $actual_hash"
}

require_tree_package() {
  local tree="$1"
  local exact="$2"
  grep -qE "^${exact}( \(.*\))?$" <<< "$tree" || fail "release graph lacks $exact"
}

# First-source exact selection and the constructive platform boundary. The five optional host
# dependencies must exist only in the macOS/Windows target table, never the unconditional block.
grep -qxF 'tauri = { version = "=2.11.5", default-features = false, features = ["wry"] }' Cargo.toml \
  || fail 'Tauri exact pin/default-features/wry selection drifted'
grep -qxF 'sys-locale = "=0.3.2"' Cargo.toml || fail 'sys-locale exact pin drifted'
grep -qxF 'tauri-build = { version = "=2.6.3", default-features = false, features = ["config-json"] }' Cargo.toml \
  || fail 'macOS launcher context generator exact pin drifted'
grep -qxF 'desktop-launcher = ["desktop-local-runtime", "postgres-maintenance", "dep:tauri-build"]' \
  crates/openbot-desktop/Cargo.toml || fail 'macOS launcher feature boundary drifted'
grep -qxF 'tauri-build = { workspace = true, optional = true }' \
  crates/openbot-desktop/Cargo.toml || fail 'macOS context generator must be optional and inherited'
grep -qxF '[target.'"'"'cfg(target_os = "macos")'"'"'.build-dependencies]' \
  crates/openbot-desktop/Cargo.toml || fail 'launcher build dependency lost its macOS host boundary'
grep -qxF 'tauri-host = ["dep:http", "dep:serde", "dep:serde_json", "dep:sys-locale", "dep:tauri"]' \
  crates/openbot-desktop/Cargo.toml || fail 'tauri-host feature boundary drifted'
grep -qxF '[target.'"'"'cfg(any(target_os = "macos", target_os = "windows"))'"'"'.dependencies]' \
  crates/openbot-desktop/Cargo.toml || fail 'Desktop host dependencies are not target-scoped'
for exact in \
  'http = { workspace = true, optional = true }' \
  'serde = { workspace = true, optional = true }' \
  'serde_json = { workspace = true, optional = true }' \
  'sys-locale = { workspace = true, optional = true }' \
  'tauri = { workspace = true, optional = true }'; do
  [[ "$(grep -cF "$exact" crates/openbot-desktop/Cargo.toml)" -eq 1 ]] \
    || fail "Desktop host dependency declaration drifted: $exact"
done
grep -qxF 'TEST_SWIFT_RS = { value = "false", force = true }' .cargo/config.toml \
  || fail 'TEST_SWIFT_RS must be force-disabled'

linux_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target x86_64-unknown-linux-gnu -e normal --prefix none --locked --offline | sort -u)"
linux_arm_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target aarch64-unknown-linux-gnu -e normal --prefix none --locked --offline | sort -u)"
mac_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target aarch64-apple-darwin -e normal --prefix none --locked --offline | sort -u)"
windows_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target x86_64-pc-windows-msvc -e normal --prefix none --locked --offline | sort -u)"
wasm_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target wasm32-unknown-unknown -e normal --prefix none --locked --offline | sort -u)"
all_build_tree="$(cargo tree -p openbot-desktop --features tauri-host \
  --target all -e normal,build --prefix none --locked --offline | sort -u)"

# The new product feature must not turn its build-time Tauri generator into a runtime dependency,
# or introduce a native WebView/Server SSO graph on unsupported targets. Build dependencies are
# selected for the host: build.rs separately checks CARGO_CFG_TARGET_OS before generating context.
launcher_mac_normal="$(cargo tree -p openbot-desktop --features desktop-launcher \
  --target aarch64-apple-darwin -e normal --prefix none --locked --offline | sort -u)"
launcher_mac_build="$(cargo tree -p openbot-desktop --features desktop-launcher \
  --target aarch64-apple-darwin -e normal,build --prefix none --locked --offline | sort -u)"
launcher_linux_normal="$(cargo tree -p openbot-desktop --features desktop-launcher \
  --target x86_64-unknown-linux-gnu -e normal --prefix none --locked --offline | sort -u)"
require_tree_package "$launcher_mac_build" 'tauri-build v2.6.3'
if grep -Eq '^tauri-build v' <<< "$launcher_mac_normal"; then
  fail 'Tauri context generator became a launcher runtime dependency'
fi
if grep -Eq '^(tauri[^ ]*|wry|sys-locale|gtk[^ ]*|webkit2gtk[^ ]*) v' <<< "$launcher_linux_normal"; then
  fail 'launcher feature leaked a native WebView into the Linux runtime graph'
fi
if grep -Eq '^(samael|xmlsec|openssl|openssl-sys) v' <<< "$launcher_mac_normal"; then
  fail 'macOS product launcher pulled Server SSO/XMLSec/OpenSSL'
fi

if grep -Eq '^(tauri|tauri-|wry|sys-locale|objc2|objc2-|swift-rs|webview2-com|webview2-com-sys|gtk|gtk-sys|gdk|gdk-sys|atk|atk-sys|glib|glib-sys|webkit2gtk|webkit2gtk-sys) v' <<< "$linux_tree"; then
  fail 'Tauri/native WebView packages leaked into the Linux Server/Web graph'
fi
if grep -Eq '^(tauri|tauri-|wry|sys-locale|objc2|objc2-|swift-rs|webview2-com|webview2-com-sys|gtk|gtk-sys|gdk|gdk-sys|atk|atk-sys|glib|glib-sys|webkit2gtk|webkit2gtk-sys) v' <<< "$linux_arm_tree"; then
  fail 'Tauri/native WebView packages leaked into the Linux arm64 Server graph'
fi
if grep -Eq '^(tauri|tauri-|wry|sys-locale|objc2|objc2-|swift-rs|webview2-com|webview2-com-sys|gtk|gtk-sys|gdk|gdk-sys|atk|atk-sys|glib|glib-sys|webkit2gtk|webkit2gtk-sys) v' <<< "$wasm_tree"; then
  fail 'Tauri/native WebView packages leaked into the WASM graph'
fi

# cargo-audit scans Cargo.lock without dependency reachability and therefore reports this exact
# Linux-GTK-only set even though no released target reaches it. Keep the negative proof explicit;
# target-aware cargo-deny remains red only for the five UNIC records below.
for released_tree in "$linux_tree" "$linux_arm_tree" "$mac_tree" "$windows_tree" "$wasm_tree"; do
  if grep -Eq '^(proc-macro-error v1\.0\.4|gdkwayland-sys v0\.18\.2|gdk v0\.18\.2|atk v0\.18\.2|gtk v0\.18\.2|atk-sys v0\.18\.2|gdk-sys v0\.18\.2|gtk3-macros v0\.18\.2|gtk-sys v0\.18\.2|glib v0\.18\.5)( \(.*\))?$' <<< "$released_tree"; then
    fail 'Cargo.lock-only GTK advisory package became reachable on a release target'
  fi
done

for exact in \
  'tauri v2.11.5' 'tauri-runtime v2.11.3' 'tauri-runtime-wry v2.11.4' \
  'wry v0.55.1' 'sys-locale v0.3.2' 'objc2 v0.6.4' \
  'objc2-exception-helper v0.1.1' 'swift-rs v1.0.8'; do
  require_tree_package "$mac_tree" "$exact"
done
for exact in \
  'tauri v2.11.5' 'tauri-runtime v2.11.3' 'tauri-runtime-wry v2.11.4' \
  'wry v0.55.1' 'sys-locale v0.3.2' 'webview2-com-sys v0.38.2'; do
  require_tree_package "$windows_tree" "$exact"
done
# A macOS host cross-querying a Windows target does not select Windows-host build dependencies.
# The actual Windows-native graph (and cargo-deny target scan) reaches vswhom-sys through
# tauri-build/embed-resource; the all-target build graph is the host-independent proof available
# on this machine, while the exact source hash below prevents drift.
require_tree_package "$all_build_tree" 'vswhom-sys v0.1.3'

# These five MPL packages and five UNIC packages are real runtime edges on both Desktop targets.
# The guard records their exact shape but deliberately does not turn the pending legal/security
# decision into a license allow or RustSec ignore.
for exact in \
  'cssparser v0.36.0' 'cssparser-macros v0.6.1' 'dtoa-short v0.3.5' \
  'option-ext v0.2.0' 'selectors v0.36.1' \
  'unic-char-property v0.9.0' 'unic-char-range v0.9.0' 'unic-common v0.9.0' \
  'unic-ucd-ident v0.9.0' 'unic-ucd-version v0.9.0' 'urlpattern v0.3.0'; do
  require_tree_package "$mac_tree" "$exact"
  require_tree_package "$windows_tree" "$exact"
done

# Actual custom-build entrypoints in the released graphs. Hash equality is stronger than keyword
# scans: any change to side effects requires a fresh human audit before cargo-deny can stay green.
check_hash indexmap-1.9.3 build.rs 558b4d0b9e9b3a44f7e1a2b69f7a7567ea721cd45cb54f4e458e850bf702f35c
check_hash objc2-0.6.4 build.rs f13d2effabc1cfa07fa5018c78eadc645914d676c034adf78acb24b8b419ce7a
check_hash objc2-exception-helper-0.1.1 build.rs 6c338b9ad9f2d47c6c9d4e3d9d604334828da36dfda4bc4d999b99aab005ceba
check_hash schemars-0.8.22 build.rs 5ef3c87640a839e95aa892c4dbc9557d8b6437caa697b53a598954cf471e2303
check_hash selectors-0.36.1 build.rs 36ba09a8d2089d0cae8e310829ecf0e94bcbaa87e775a6578c7d2f0459a5b6ca
check_hash swift-rs-1.0.8 src-rs/test-build.rs 82941bdb037e5479003967346ae2f1932391770c8515f4b10cc90569a9b171a1
check_hash swift-rs-1.0.8 src-rs/build.rs e18db702ab5655fa7659047b0892b4caff44bc5a497ccc4fa3c6c0246a7a6a19
check_hash swift-rs-1.0.8 Cargo.toml 85204ee8bf319d47ea67c31eb66fa4a5479bf44d6355ff76a4f717d15213c9f2
check_hash tauri-2.11.5 build.rs 62d1a1e16affe3c9b59d6766159a568255e385cab969ce4149ad6081276715bd
check_hash tauri-runtime-2.11.3 build.rs 68b2727346e58a9963803a75ac29695b500aaa7d0673e18551465502b60cbf11
check_hash tauri-runtime-wry-2.11.4 build.rs 68b2727346e58a9963803a75ac29695b500aaa7d0673e18551465502b60cbf11
check_hash vswhom-sys-0.1.3 build.rs 3adb4b0f64aa6af4ca91aa3b0bacf81eb75e98b5587a625568ed825eb18a6f17
check_hash web_atoms-0.2.6 build.rs 8b50922bbb295e90a26edc3e2ab34f068fee930cefd73ae03cca210cf08f9d89
check_hash webview2-com-sys-0.38.2 build.rs ea73d2566f434a25e8172d0fb9eaad5fa29ee687a8f05b9c2be02b19e4366e16
check_hash wry-0.55.1 build.rs 3c3153deae92302ed707b06ecfafffbf256f0ef4157b813c3120887c8010d7db

# Exact MPL evidence currently present in the crates.io packages. selectors carries per-file MPL
# notices rather than a standalone license file, so lock both its manifest declaration and lib root.
check_hash cssparser-0.36.0 LICENSE fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85
check_hash cssparser-macros-0.6.1 LICENSE fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85
check_hash dtoa-short-0.3.5 LICENSE 1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5
check_hash option-ext-0.2.0 LICENSE.txt 66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172
check_hash selectors-0.36.1 Cargo.toml c4d292da59a7b7787100f0839b7c18d9a2fa661ab7906d1617137469e1aca2da
check_hash selectors-0.36.1 lib.rs d54c6e13e9e952dac17d209171df8657e3cae93beaddace4906150cdec8d02e9

# Microsoft WebView2 packaged loader payloads. The Windows x64 build consumes x64; all archive
# members stay exact so cargo-deny cannot silently acquire a new binary through another directory.
check_hash webview2-com-sys-0.38.2 arm64/WebView2Loader.dll df5816669f5123595c475d97929240d7d0e04f0bdc7dbe18af1dda42348b73a6
check_hash webview2-com-sys-0.38.2 arm64/WebView2Loader.dll.lib d70271daa44507865ca0696cd1c1ede5e58e694eec74cb2d06e17dbbe205e9a2
check_hash webview2-com-sys-0.38.2 arm64/WebView2LoaderStatic.lib 506ffde430bee7f91f2ce1a078effb5289b7cec3b0c7283647f0842def524ab4
check_hash webview2-com-sys-0.38.2 x64/WebView2Loader.dll 8427b1fc58ec707813e5c0a51eb5d69397bb333250a7b891be4d3b123f1e0f1c
check_hash webview2-com-sys-0.38.2 x64/WebView2Loader.dll.lib bfc8ccaaa056be95243a5b66a827e5849d2bb39676fca4dcc2053796d8e15c6d
check_hash webview2-com-sys-0.38.2 x64/WebView2LoaderStatic.lib 0659b741bde6348d4c4a6ec4ceb9af50e3d0048ed9cd3c8659bccbb61fde55ee
check_hash webview2-com-sys-0.38.2 x86/WebView2Loader.dll 44ab92c2246ebfb5f98aa5726626fb44beb61543f2ef1803338af9fd295e63f0
check_hash webview2-com-sys-0.38.2 x86/WebView2Loader.dll.lib a3ec0ee539d58fe72391f2e89cb814f96fab721c6d8d30953d152ea95dffad49
check_hash webview2-com-sys-0.38.2 x86/WebView2LoaderStatic.lib 6649ce9ca24e7a5693ee54178f42e0378004ce537d82d15354e6c9adb467bc16

for advisory_id in \
  RUSTSEC-2025-0075 RUSTSEC-2025-0080 RUSTSEC-2025-0081 RUSTSEC-2025-0098 RUSTSEC-2025-0100; do
  advisory_candidates=("$cargo_cache_root"/advisory-db/crates/*/"$advisory_id.md")
  [[ ${#advisory_candidates[@]} -eq 1 ]] || fail "$advisory_id record missing or ambiguous"
  grep -qxF 'informational = "unmaintained"' "${advisory_candidates[0]}" \
    || fail "$advisory_id is no longer informational-only"
  grep -qxF 'patched = []' "${advisory_candidates[0]}" \
    || fail "$advisory_id now has a patched release"
done

for name in indexmap objc2 objc2-exception-helper schemars selectors swift-rs tauri \
  tauri-runtime tauri-runtime-wry vswhom-sys web_atoms webview2-com-sys wry; do
  grep -qxF "    \"$name\"," deny.toml || fail "audited build script is not allowlisted: $name"
done

printf '%s\n' \
  'Tauri dependency guard: ok (Linux host graph absent; 13 build scripts; 9 WebView2 payloads; policy blockers remain MPL-2.0 x5 + unmaintained UNIC x5 + Cargo Vet)'
