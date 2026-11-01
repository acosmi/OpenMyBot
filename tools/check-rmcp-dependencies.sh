#!/usr/bin/env bash
# G4 RMCP gate: pinned graph/provenance plus Batch105 protocol-cancellation wiring.
set -euo pipefail

fail() {
  printf 'RMCP dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

grep -qF 'rmcp = { version = "=3.1.4", default-features = false, features = ["client", "transport-streamable-http-client"] }' Cargo.toml || fail 'rmcp must remain exact 3.1.4 with client Streamable HTTP only'
grep -qF 'sse-stream = "=0.2.4"' Cargo.toml || fail 'sse-stream exact pin drifted'
grep -qF 'jsonschema = { version = "=0.51.0", default-features = false }' Cargo.toml || fail 'jsonschema must remain exact and disable HTTP/file resolver defaults'

normal_tree=$(cargo tree -p openbot-infra -e normal --prefix none --locked)
for exact in 'rmcp v3.1.4' 'sse-stream v0.2.4' 'jsonschema v0.51.0' 'jsonschema-regex v0.51.0' 'jsonschema-value v0.51.0' 'referencing v0.51.0'; do
  grep -qxF "$exact" <<< "$normal_tree" || fail "production dependency graph lacks $exact"
done
if grep -Eq '^(reqwest|native-tls|aws-lc-rs|aws-lc-sys) v' <<< "$normal_tree"; then
  fail 'RMCP/schema graph introduced a second HTTP/TLS implementation'
fi

feature_tree=$(cargo tree -p openbot-infra -e features,no-dev --prefix none --locked)
for required in 'rmcp feature "client"' 'rmcp feature "transport-streamable-http-client"'; do
  grep -qxF "$required" <<< "$feature_tree" || fail "missing required feature $required"
done
for forbidden in 'rmcp feature "server"' 'rmcp feature "transport-streamable-http-server"' 'rmcp feature "transport-io"' 'rmcp feature "transport-child-process"' 'rmcp feature "reqwest"' 'jsonschema feature "resolve-http"' 'jsonschema feature "resolve-file"' 'jsonschema feature "tls-aws-lc-rs"' 'jsonschema feature "tls-ring"'; do
  if grep -qxF "$forbidden" <<< "$feature_tree"; then
    fail "unreviewed production feature enabled: $forbidden"
  fi
done

rmcp_callers=$(rg -l 'rmcp::' crates/*/src --glob '*.rs' --glob '!crates/omb-*/**' | sort)
# 测试夹具：mcp/selected_target_tests.rs 只经 mcp.rs 的 #[cfg(test)] mod 编入（PR #118）。
[[ "$rmcp_callers" == $'crates/openbot-infra/src/mcp.rs\ncrates/openbot-infra/src/mcp/selected_target_tests.rs' ]] || fail "rmcp types escaped the single infra boundary: [$rmcp_callers]"
for anchor in \
  'send_cancellable_request(request, options)' \
  'notify_cancelled(CancelledNotificationParam::new(' \
  '.reset_timeout_on_progress()' \
  '.with_max_total_timeout(MCP_CALL_TIMEOUT)'; do
  grep -qF "$anchor" crates/openbot-infra/src/mcp.rs \
    || fail "RMCP request cancellation/progress boundary drifted: $anchor"
done
grep -qF '.with_tool_cancellations(tool_cancellations.clone())' \
  crates/openbot-infra/src/application_assembly.rs \
  || fail 'shared ApplicationService assembly no longer binds exact-call cancellation'
for host in crates/openbot-server/src/main.rs crates/openbot-desktop/src/desktop_agent_runtime.rs; do
  grep -qF 'AuthorizedAgentToolGateway::with_sequence_and_cancellations(' "$host" \
    || fail "$host bypasses the shared tool cancellation registry"
done
grep -qF 'jsonschema::PatternOptions::regex()' crates/openbot-infra/src/mcp_catalog.rs || fail 'untrusted JSON Schema patterns must use the linear regex engine'
if rg -q 'jsonschema::validator_for|jsonschema::draft[0-9]+::validator_for' crates/openbot-infra/src; then
  fail 'a JSON Schema compile path bypasses the bounded compile_schema configuration'
fi

metadata=$(cargo metadata --format-version 1 --locked)
printf '%s' "$metadata" | python3 -c '
import hashlib,json,pathlib,sys
d=json.load(sys.stdin)
expected={
  "ahash":("0.8.12",22,"d7dd5428c78b80bb3c99068561641ec661f0f94defbda17f85b443e358ab6396"),
  "ref-cast":("1.0.27",50,"095bc1870b75dd5c80a68bddaae03d2de9f817e134b026ebf3f63e0ff81cf5ca"),
  "rmcp":("3.1.4",23,"31b905abf91292bab290271e993e347e06a1944e6305f742f69dbd01e6b89349"),
  "unicode-general-category":("1.1.0",201,"a877183b60fdc9846063f7ed5a1dc23f8ef26e1ff4994bc4cfc7418ddb4ec48e"),
}
seen={}
for package in d["packages"]:
    if package["name"] not in expected or package["version"] != expected[package["name"]][0]:
        continue
    path=pathlib.Path(package["manifest_path"]).parent/"build.rs"
    raw=path.read_bytes()
    seen[package["name"]]=(len(raw.splitlines()),hashlib.sha256(raw).hexdigest())
assert seen=={name:(value[1],value[2]) for name,value in expected.items()},(seen,expected)
rmcp=[p for p in d["packages"] if p["name"]=="rmcp" and p["version"]=="3.1.4"]
assert len(rmcp)==1,rmcp
root=pathlib.Path(rmcp[0]["manifest_path"]).parent
vcs=json.loads((root/".cargo_vcs_info.json").read_text())
assert vcs["git"]["sha1"]=="4a738b9dd99eaca418b614afa433a0cbdaf8d056",vcs
build_workspace=root.parent.parent
assert not ((build_workspace/".git").exists() and (build_workspace/".githooks").exists()),build_workspace
' || fail 'build.rs hashes or rmcp crates.io VCS provenance drifted'

python3 -c '
import tomllib
d=tomllib.load(open("supply-chain/config.toml","rb"))
expected=set("ahash base64 borrow-or-share email_address fancy-regex fluent-uri fraction futures futures-executor futures-io futures-macro jsonschema jsonschema-regex jsonschema-value micromap num num-bigint num-cmp num-complex num-rational outref referencing rmcp schemars_derive serde_derive_internals sse-stream strum strum_macros tokio-stream unicode-general-category uuid-simd vsimd".split())
seen=set()
for name,entries in d.get("exemptions",{}).items():
    for entry in entries:
        notes=entry.get("notes","")
        if "G4 Batch 11" in notes:
            assert entry.get("criteria")=="safe-to-deploy",(name,entry)
            assert "owner=security" in notes and "not a full source audit" in notes,(name,entry)
            seen.add(name)
assert seen==expected,(seen,expected)
' || fail 'Batch 11 Cargo Vet exact exemption set/owner/honesty drifted'

grep -qF '117829c3ca21efb132d81a44b55363d395ab8eea18526873bc828da4c0e5f038' NOTICE \
  || fail 'jsonschema MIT license evidence is missing from NOTICE'
python3 -c '
import json
d=json.load(open("provenance/sources.spdx.json"))
expected={
 "SPDXRef-Package-rmcp":("3.1.4","Apache-2.0"),
 "SPDXRef-Package-jsonschema":("0.51.0","MIT"),
 "SPDXRef-Package-openai-dotnet-recorded-trace":("19d0a3cb8e0cf0f3137a5c56c3c70a0c3f6c96f5","MIT"),
 "SPDXRef-Package-ag-ui-core-schema-0-0-57":("0.0.57","MIT"),
 "SPDXRef-Package-anthropic-go-recorded-trace":("e9c104e7e5fb80a26ff26e398c0e4e3fe1fe7f33","MIT"),
 "SPDXRef-Package-anthropic-php-recorded-trace":("93aa419595dceeb7062292e09406b4e2a63b96e1","MIT"),
 "SPDXRef-Package-acosmi-sdk-5-0-0":("5.0.0","MIT"),
 "SPDXRef-Package-async-stream-0-3-6":("0.3.6","MIT"),
 "SPDXRef-Package-async-stream-impl-0-3-6":("0.3.6","MIT"),
}
seen={p["SPDXID"]:(p.get("versionInfo"),p.get("licenseDeclared")) for p in d["packages"] if p["SPDXID"] in expected}
assert seen==expected,(seen,expected)
ids=[p["SPDXID"] for p in d["packages"]]
assert len(d["packages"])==62 and len(ids)==len(set(ids)),(len(d["packages"]),len(set(ids)))
' || fail 'RMCP/schema SPDX identity, license declaration or package count drifted'

printf 'RMCP dependency guard: ok (rmcp 3.1.4 commit 4a738b9d; protocol cancel/progress; no reqwest; 4 pinned build.rs; 32 explicit non-audit exemptions)\n'
