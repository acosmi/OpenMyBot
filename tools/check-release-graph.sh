#!/usr/bin/env bash
# Supply-chain, source and secret checks on the actual macOS release feature graph of the desktop
# launcher and on the built app bundle (supply-chain section and macOS release acceptance).
#
# Read-only: it never installs a tool, never fetches advisory or audit data and never edits
# deny.toml or supply-chain/. A missing tool or an option the installed tool does not support is
# reported as not_evaluated and fails the run, so a missing check can never read as a pass.
set -euo pipefail

usage() {
  printf 'usage: %s --app <Wrok Bot.app> [--target <triple>] [--out <dir>] [--release]\n' "$0" >&2
  exit 2
}

app=''
target=aarch64-apple-darwin
out=''
release=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) app="${2:?}"; shift 2 ;;
    --target) target="${2:?}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --release) release=true; shift ;;
    *) usage ;;
  esac
done
[[ -n "$app" ]] || usage
[[ -d "$app/Contents" ]] || { printf 'not an app bundle (no Contents/ directory): %s\n' "$app" >&2; exit 2; }
app="$(cd "$app" && pwd)"
[[ -n "$out" ]] || out="$(mktemp -d)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
cd "$(dirname "$0")/.."

results="$out/checks.jsonl"
: > "$results"
# record <name> <pass|fail|not_evaluated> <exit code|null> <version> <command> <detail json>
record() {
  jq -cn --arg name "$1" --arg status "$2" --argjson exit_code "$3" --arg version "$4" \
    --arg command "$5" --argjson detail "$6" \
    '{name: $name, status: $status, exit_code: $exit_code, version: $version, command: $command}
     + $detail' >> "$results"
}

# (a) The release graph: normal and build edges of the launcher feature for the release target.
tree_cmd=(cargo tree -p openbot-desktop --features desktop-launcher --target "$target"
  -e normal,build --prefix none --locked --offline)
graph="$out/release-graph.txt"
graph_json=null
rc=0
"${tree_cmd[@]}" > "$out/cargo-tree.raw" 2> "$out/cargo-tree.log" || rc=$?
if [[ $rc -eq 0 ]]; then
  awk '$2 ~ /^v[0-9]/ {print $1 " " $2}' "$out/cargo-tree.raw" | sort -u > "$graph"
  graph_json="$(jq -Rsc 'split("\n") | map(select(length > 0))' "$graph")"
  record cargo-tree pass 0 "$(cargo --version)" "${tree_cmd[*]}" \
    "$(jq -cn --argjson n "$(wc -l < "$graph")" '{packages: $n, list: "release-graph.txt"}')"
else
  record cargo-tree fail "$rc" "$(cargo --version)" "${tree_cmd[*]}" '{"log": "cargo-tree.log"}'
fi

# (b) cargo-deny rooted at the launcher package with only the launcher feature. deny.toml sets
# graph.all-features, which cargo-deny ORs with the command line, so this run reads a derived copy
# without that one line; every policy table stays as reviewed. A single-package root leaves other
# members' workspace dependencies unused; the workspace-wide deny run owns that lint.
deny_cfg="$out/deny.release-graph.toml"
sed '/^all-features = true$/d' deny.toml > "$deny_cfg"
deny_cmd=(cargo deny --log-level warn --manifest-path crates/openbot-desktop/Cargo.toml
  --target "$target" --features desktop-launcher --exclude-dev --locked --offline
  check --config "$deny_cfg" --allow unused-workspace-dependency
  bans licenses sources advisories)
if ! command -v cargo-deny > /dev/null; then
  record cargo-deny not_evaluated null '' "${deny_cmd[*]}" '{"reason": "cargo-deny is not installed"}'
else
  rc=0
  "${deny_cmd[@]}" > "$out/cargo-deny.log" 2>&1 || rc=$?
  if [[ $rc -ne 0 ]] && grep -Eq 'unexpected argument|unrecognized' "$out/cargo-deny.log"; then
    record cargo-deny not_evaluated null "$(cargo deny --version)" "${deny_cmd[*]}" \
      '{"reason": "installed cargo-deny does not support the feature-graph options", "log": "cargo-deny.log"}'
  else
    counts="$(jq -cn --argjson e "$(grep -Ec '^error\[' "$out/cargo-deny.log" || true)" \
      --argjson w "$(grep -Ec '^warning\[' "$out/cargo-deny.log" || true)" \
      '{errors: $e, warnings: $w, log: "cargo-deny.log"}')"
    record cargo-deny "$([[ $rc -eq 0 ]] && echo pass || echo fail)" "$rc" \
      "$(cargo deny --version)" "${deny_cmd[*]}" "$counts"
  fi
fi

# (c) cargo-audit and cargo-vet read the whole lockfile, not the feature graph. Each finding is
# marked by whether its exact package version is in the release graph (null if (a) failed).
# The audit waivers are the reviewed ones in the manual CI workflow and deny.toml.
audit_cmd=(cargo audit --no-fetch --deny warnings --json --ignore RUSTSEC-2023-0071
  --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2026-0173)
if ! command -v cargo-audit > /dev/null; then
  record cargo-audit not_evaluated null '' "${audit_cmd[*]}" '{"reason": "cargo-audit is not installed"}'
else
  rc=0
  "${audit_cmd[@]}" > "$out/cargo-audit.json" 2> "$out/cargo-audit.log" || rc=$?
  # The database revision makes a pass on a stale advisory database visible.
  if detail="$(jq -ce --argjson graph "$graph_json" '
      def mark: (.package.name + " v" + .package.version) as $p
        | {id: (.advisory.id // null), package: $p,
           in_release_graph: (if $graph == null then null else any($graph[]; . == $p) end)};
      {scope: "whole lockfile, not the feature subgraph", log: "cargo-audit.log",
       database: {last_commit: .database["last-commit"], last_updated: .database["last-updated"],
                  advisory_count: .database["advisory-count"]},
       vulnerabilities: [.vulnerabilities.list[] | mark],
       warnings: [.warnings[]?[] | mark + {kind}]}
      | .vulnerability_count = (.vulnerabilities | length)
      | .warning_count = (.warnings | length)' "$out/cargo-audit.json" 2> /dev/null)"; then
    record cargo-audit "$([[ $rc -eq 0 ]] && echo pass || echo fail)" "$rc" \
      "$(cargo audit --version)" "${audit_cmd[*]}" "$detail"
  else
    record cargo-audit not_evaluated "$rc" "$(cargo audit --version)" "${audit_cmd[*]}" \
      '{"reason": "no cargo-audit JSON report of the expected shape", "log": "cargo-audit.log"}'
  fi
fi

vet_cmd=(cargo vet --locked --output-format json)
if ! command -v cargo-vet > /dev/null; then
  record cargo-vet not_evaluated null '' "${vet_cmd[*]}" '{"reason": "cargo-vet is not installed"}'
else
  rc=0
  "${vet_cmd[@]}" > "$out/cargo-vet.json" 2> "$out/cargo-vet.log" || rc=$?
  if detail="$(jq -ce --argjson graph "$graph_json" '
      {scope: "whole lockfile, not the feature subgraph", log: "cargo-vet.log", conclusion,
       unvetted: [.failures[]? | (.name + " v" + .version) as $p
        | {package: $p, missing_criteria,
           in_release_graph: (if $graph == null then null else any($graph[]; . == $p) end)}]}
      | .unvetted_count = (.unvetted | length)' "$out/cargo-vet.json" 2> /dev/null)"; then
    record cargo-vet "$([[ $rc -eq 0 ]] && echo pass || echo fail)" "$rc" \
      "$(cargo vet --version)" "${vet_cmd[*]}" "$detail"
  else
    record cargo-vet not_evaluated "$rc" "$(cargo vet --version)" "${vet_cmd[*]}" \
      '{"reason": "no cargo-vet JSON report of the expected shape", "log": "cargo-vet.log"}'
  fi
fi

# (d) Mach-O inventory under Contents/, found by magic bytes. gitleaks skips binary files, so each
# Mach-O is also dumped with strings -a for the secret scan, and its entitlements are read for (f).
# strings reads the file from stdin so it sees every byte; given a path, macOS strings parses the
# Mach-O and skips data outside the architecture slices. The C locale keeps the dump ASCII, because
# a UTF-8 locale lets raw high bytes through and gitleaks then skips the dump as binary.
mkdir -p "$out/strings"
macho_count=0
macho_bytes=0
strings_bytes=0
dlv_files=()
while IFS= read -r -d '' file; do
  case "$(head -c 4 "$file" | xxd -p)" in
    cffaedfe | cefaedfe | cafebabe | cafebabf) ;;
    *) continue ;;
  esac
  rel="${file#"$app"/}"
  mkdir -p "$(dirname "$out/strings/$rel")"
  LC_ALL=C strings -a < "$file" > "$out/strings/$rel.txt"
  macho_count=$((macho_count + 1))
  macho_bytes=$((macho_bytes + $(wc -c < "$file")))
  strings_bytes=$((strings_bytes + $(wc -c < "$out/strings/$rel.txt")))
  if codesign -d --entitlements - --xml "$file" 2> /dev/null | tr -d ' \t\n' \
    | grep -q '<key>com.apple.security.cs.disable-library-validation</key><true/>'; then
    dlv_files+=("$rel")
  fi
done < <(find "$app/Contents" -type f -print0)

# (e) Secret scan with the repository rules of the bundle's text files and of the Mach-O strings.
# Inline gitleaks:allow markers are disabled and the repository's ignore file is not used, as in the
# repository guard; a .gitleaksignore inside the scanned tree itself is still honoured by gitleaks.
# The reports keep matched values redacted.
for scope in bundle macho-strings; do
  if [[ $scope == bundle ]]; then
    src="$app"
    extra='{}'
  else
    src="$out/strings"
    extra="$(jq -cn --argjson files "$macho_count" --argjson bytes "$macho_bytes" \
      --argjson strings_bytes "$strings_bytes" '{macho_files: $files, macho_bytes: $bytes,
        strings_bytes: $strings_bytes,
        note: "strings -a cannot see secrets inside compressed embedded assets such as the UI bundle"}')"
  fi
  leaks_cmd=(gitleaks dir "$src" --config .gitleaks.toml --redact=100 --no-banner --no-color
    --ignore-gitleaks-allow --gitleaks-ignore-path "$out/no-ignored-findings"
    --report-format json --report-path "$out/gitleaks-$scope.json")
  if ! command -v gitleaks > /dev/null; then
    record "gitleaks-$scope" not_evaluated null '' "${leaks_cmd[*]}" \
      '{"reason": "gitleaks is not installed"}'
    continue
  fi
  rc=0
  "${leaks_cmd[@]}" > "$out/gitleaks-$scope.log" 2>&1 || rc=$?
  findings=null
  [[ -f "$out/gitleaks-$scope.json" ]] && findings="$(jq length "$out/gitleaks-$scope.json")"
  record "gitleaks-$scope" "$([[ $rc -eq 0 ]] && echo pass || echo fail)" "$rc" \
    "$(gitleaks version)" "${leaks_cmd[*]}" "$(jq -cn --argjson n "$findings" --argjson extra "$extra" \
      --arg scope "$scope" '{findings: $n, report: "gitleaks-\($scope).json",
        log: "gitleaks-\($scope).log"} + $extra')"
done
# The dumps hold any secret in plain text; only the redacted reports and the summary stay.
rm -rf "$out/strings"

# (f) Release signing posture. An ad-hoc signed PostgreSQL bundle carries the
# disable-library-validation entitlement, so neither may reach a release. Without --release the
# findings are informational only.
manifest="$app/Contents/Resources/postgres/manifest.json"
pg_identity=null
[[ -f "$manifest" ]] && pg_identity="$(jq -c '.signing_identity' "$manifest")"
signing_detail="$(jq -cn --argjson identity "$pg_identity" --argjson release "$release" \
  '$ARGS.positional as $dlv | {release: $release, postgres_manifest: "Contents/Resources/postgres/manifest.json",
    postgres_signing_identity: $identity, disable_library_validation: $dlv,
    problems: ([if $identity == null then "postgres manifest or signing_identity missing" else empty end,
                if $identity == "-" then "postgres bundle is ad-hoc signed" else empty end,
                if $dlv != [] then "Mach-O carries disable-library-validation" else empty end])}' \
  --args ${dlv_files[@]+"${dlv_files[@]}"})"
if ! $release; then
  signing_status=info
elif [[ "$(jq '.problems | length' <<< "$signing_detail")" -eq 0 ]]; then
  signing_status=pass
else
  signing_status=fail
fi
record release-signing "$signing_status" null '' \
  'codesign -d --entitlements - --xml <each Mach-O under Contents/>' "$signing_detail"

# (g) Summary. Every check must pass; not_evaluated is a failure of the gate, never a pass.
jq -s --arg app "$app" --arg target "$target" --argjson release "$release" '{
    app: $app, target: $target, release: $release, features: ["desktop-launcher"], package: "openbot-desktop",
    checks: .,
    failed: [.[] | select(.status == "fail") | .name],
    not_evaluated: [.[] | select(.status == "not_evaluated") | .name]
  } | .result = (if (.failed + .not_evaluated) == [] then "pass" else "fail" end)' \
  "$results" > "$out/summary.json"

jq -r '.checks[] | "\(.name): \(.status)"' "$out/summary.json"
printf 'summary: %s\n' "$out/summary.json"
if [[ "$(jq -r .result "$out/summary.json")" != pass ]]; then
  jq -r '"release graph check failed: failed=\(.failed) not_evaluated=\(.not_evaluated)"' \
    "$out/summary.json" >&2
  exit 1
fi
printf '%s\n' 'release graph check: ok'
