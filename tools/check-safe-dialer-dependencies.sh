#!/usr/bin/env bash
# W-7 / R29：HTTP safe dialer 的依赖、feature、唯一调用面与 C/汇编供应链 guard。
set -euo pipefail

fail() {
  printf 'safe dialer dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

if [[ ${RING_PREGENERATE_ASM+x} ]]; then
  fail 'RING_PREGENERATE_ASM 不得由构建环境注入；正常 crates.io build 必须消费锁定 pregenerated 产物'
fi

normal_tree=$(cargo tree -p openbot-infra -e normal --prefix none --locked)
for exact in \
  'ipnet v2.12.1' \
  'ring v0.17.14' \
  'rustls v0.23.43' \
  'rustls-pki-types v1.15.1' \
  'rustls-webpki v0.103.15' \
  'tokio-rustls v0.26.4' \
  'webpki-roots v1.0.9'; do
  grep -qxF "$exact" <<< "$normal_tree" || fail "依赖图缺少精确版本 $exact"
done

if grep -Eq '^(reqwest|native-tls|aws-lc-rs|aws-lc-sys) v' <<< "$normal_tree"; then
  fail 'openbot-infra 图出现第二 HTTP/TLS 路径（reqwest/native-tls/aws-lc）'
fi

# W-7b 按 R29 另立审计后为 SAML XMLDSig 引入 OpenSSL；它不是 safe dialer TLS 后端。
# 源码调用面必须仍然只在 saml.rs，若扩到 HTTP/client 代码则本 guard 先红。
openssl_callers=$(rg -l 'openssl::' crates/*/src --glob '*.rs' | sort)
[[ "$openssl_callers" == 'crates/openbot-infra/src/auth/sso/saml.rs' ]] \
  || fail "OpenSSL 调用面越出 SAML XML/cert 校验：[$openssl_callers]"

feature_tree=$(cargo tree -p openbot-infra -e features --prefix none --locked)
grep -qxF 'rustls feature "ring"' <<< "$feature_tree" || fail 'rustls ring feature 未启用'
for forbidden in \
  'rustls feature "aws_lc_rs"' \
  'rustls feature "prefer-post-quantum"' \
  'hyper feature "http2"' \
  'hyper feature "tracing"' \
  'hyper-util feature "client-proxy"' \
  'hyper-util feature "client-proxy-system"'; do
  if grep -qxF "$forbidden" <<< "$feature_tree"; then
    fail "出现未审 feature: $forbidden"
  fi
done

grep -qF 'openidconnect = { version = "4.0.1", default-features = false }' Cargo.toml \
  || fail 'openidconnect 必须继续关闭自带 reqwest/rustls'

network_callers=$(rg -l 'TcpStream::connect|lookup_host\(|TlsConnector|http1::handshake|reqwest::|hyper::client|tokio_rustls' crates/*/src --glob '*.rs' | sort)
# 测试夹具：标注的文件只经 #[cfg(test)] 或 #[cfg(all(test, …))] 模块编入，其回环探针不是生产出网调用方；
# provider/custom.rs 是生产文件，命中行在其 #[cfg(test)] mod v2_vault_tests 内。
expected_callers_list=(
  crates/omb-channels/src/testkit.rs # 测试夹具 PR #243（testkit feature 模块，命中在其 #[cfg(test)] mod tests 内）
  crates/openbot-computer/src/engine/process.rs
  crates/openbot-desktop/src/postgres_sidecar.rs
  crates/openbot-desktop/src/tauri_host/approval_preference_local_tests.rs # 测试夹具 PR #147
  crates/openbot-infra/src/artifact_read_authority/save_receipt_tests.rs # 测试夹具 PR #141
  crates/openbot-infra/src/artifact_read_authority/tests.rs # 测试夹具 PR #131
  crates/openbot-infra/src/db/pool/owner.rs # V7-IMPL-045 R475-B：mod capture_io 只惰性连接原 127.0.0.1:port 本机 socket
  crates/openbot-infra/src/mcp/selected_target_tests.rs # 测试夹具 PR #118
  crates/openbot-infra/src/net/safe_http.rs
  crates/openbot-infra/src/provider/custom.rs # 测试夹具 mod v2_vault_tests，PR #171
  crates/openbot-server/src/auth/gateway_authorization_journal_tests/support.rs # 测试夹具 PR #174
  crates/openbot-server/src/auth/gateway_callback_rendezvous_tests.rs # 测试夹具 PR #178
  crates/openbot-server/src/auth/gateway_registration_dispatch_tests.rs # 测试夹具 PR #175
  crates/openbot-server/src/auth/gateway_token_dispatch_tests.rs # 测试夹具 PR #179
  crates/openbot-server/src/auth/thread_history_management_tests.rs # 测试夹具 PR #181
  crates/openbot-server/src/config/single_user_transport_tests.rs # 测试夹具 PR #232
  crates/openbot-server/src/http/approvals.rs
  crates/openbot-server/src/http/artifact_save_receipt_tests.rs # 测试夹具 PR #141
  crates/openbot-server/src/http/channels.rs
  crates/openbot-server/src/http/screen.rs
  crates/openbot-server/src/http/threads.rs
  crates/openbot-server/src/http/transport_gate.rs
)
expected_callers=$(printf '%s\n' "${expected_callers_list[@]}")
[[ "$network_callers" == "$expected_callers" ]] \
  || fail "socket/DNS/TLS/HTTP client 调用面不再唯一：[$network_callers]"

# The per-scope proxy owns only its loopback listener and authenticated framing. Its sole outgoing
# capability is the private ProxyHop returned by SafeDialer; DNS/connect/HTTP handshakes stay above.
proxy_hop_callers=$(rg -l 'connect_proxy_hop\(|\.into_tunnel\(' crates/*/src --glob '*.rs' | sort)
expected_proxy_hop_callers=$'crates/openbot-infra/src/net/safe_http.rs\ncrates/openbot-infra/src/net/scope_gateway.rs'
[[ "$proxy_hop_callers" == "$expected_proxy_hop_callers" ]] \
  || fail "scope proxy hop escaped its two owning modules: [$proxy_hop_callers]"

# §10.5 第 7 项：WebSocket 客户端只在 SafeDialer::connect_websocket_stream 返回的已验证流上握手；
# tokio-tungstenite 的自拨号（connect_async 族）与自带 TLS（client_async_tls 族）入口不得出现在第一方源码。
if rg -n '\b(connect_async|client_async_tls)' crates/*/src --glob '*.rs'; then
  fail 'tokio-tungstenite 自拨号/自带 TLS 入口绕过 SafeDialer'
fi

# Seven test modules own these loopback probes. Desktop has two existing exit-observation
# probes (unclean Drop and owned orphan shutdown); every other module has exactly one.
# Pin each count and require every caller to remain after the unique cfg(test) module marker.
# Screen另有test-only fixture常量，不能把它的cfg误当作测试模块起点。实际七个tests模块均在文件末尾。
test_only_network_files=(
  crates/openbot-computer/src/engine/process.rs
  crates/openbot-desktop/src/postgres_sidecar.rs
  crates/openbot-server/src/http/approvals.rs
  crates/openbot-server/src/http/channels.rs
  crates/openbot-server/src/http/screen.rs
  crates/openbot-server/src/http/threads.rs
  crates/openbot-server/src/http/transport_gate.rs
)
for file in "${test_only_network_files[@]}"; do
  test_module_line=$(awk 'previous == "#[cfg(test)]" && $0 == "mod tests {" { print NR - 1 } { previous = $0 }' "$file")
  client_lines=$(rg -n 'TcpStream::connect|lookup_host\(|TlsConnector|http1::handshake|reqwest::|hyper::client|tokio_rustls' "$file" | cut -d: -f1)
  expected_count=1
  if [[ "$file" == crates/openbot-desktop/src/postgres_sidecar.rs ]]; then expected_count=2; fi
  actual_count=$(wc -l <<< "$client_lines" | tr -d ' ')
  [[ "$test_module_line" =~ ^[0-9]+$ && "$actual_count" -eq "$expected_count" ]] \
    || fail "test-only loopback client 数量漂移：file=$file cfg=[$test_module_line] callers=[$client_lines]"
  while IFS= read -r client_line; do
    [[ "$client_line" =~ ^[0-9]+$ ]] && (( client_line > test_module_line )) \
      || fail "loopback client 越出 cfg(test)：file=$file cfg=$test_module_line caller=$client_line"
  done <<< "$client_lines"
done

# provider/custom.rs 的唯一回环探针在其 #[cfg(test)] mod v2_vault_tests 内；生产段再出现出网调用即红。
custom_file=crates/openbot-infra/src/provider/custom.rs
custom_test_module_line=$(awk 'previous == "#[cfg(test)]" && $0 == "mod v2_vault_tests {" { print NR - 1 } { previous = $0 }' "$custom_file")
custom_client_lines=$(rg -n 'TcpStream::connect|lookup_host\(|TlsConnector|http1::handshake|reqwest::|hyper::client|tokio_rustls' "$custom_file" | cut -d: -f1)
[[ "$custom_test_module_line" =~ ^[0-9]+$ && "$custom_client_lines" =~ ^[0-9]+$ ]] \
  && (( custom_client_lines > custom_test_module_line )) \
  || fail "custom provider loopback client 越出 cfg(test)：cfg=[$custom_test_module_line] callers=[$custom_client_lines]"

metadata=$(cargo metadata --format-version 1 --locked)
ring_manifest=$(printf '%s' "$metadata" | python3 -c 'import json,sys;d=json.load(sys.stdin);m=[p["manifest_path"] for p in d["packages"] if p["name"]=="ring" and p["version"]=="0.17.14"];assert len(m)==1,m;print(m[0])')
ring_dir=${ring_manifest%/Cargo.toml}
[[ -f "$ring_dir/build.rs" ]] || fail '找不到 ring 0.17.14/build.rs'

ring_build_hash=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$ring_dir/build.rs")
[[ "$ring_build_hash" == '9d1928ffb1d8e15766c1c1b9ead73e4b81a21703dd25f7c27b87842a2e6e9cee' ]] \
  || fail "ring build.rs hash 漂移：$ring_build_hash"

ring_build_lines=$(wc -l < "$ring_dir/build.rs" | tr -d ' ')
ring_perl_count=$(find "$ring_dir/crypto" -type f -name '*.pl' | wc -l | tr -d ' ')
ring_object_count=$(find "$ring_dir/pregenerated" -type f -name '*.o' | wc -l | tr -d ' ')
[[ "$ring_build_lines" == '1044' ]] || fail "ring build.rs 行数漂移：$ring_build_lines"
[[ "$ring_perl_count" == '38' ]] || fail "ring Perl 源数量漂移：$ring_perl_count"
[[ "$ring_object_count" == '17' ]] || fail "ring 预生成对象数量漂移：$ring_object_count"

grep -qF 'include-archives = true' deny.toml || fail 'cargo-deny 必须扫描 archive/object'
grep -qF 'crate = "ring@0.17.14"' deny.toml || fail '缺 ring 精确版本 bypass'
grep -qF 'allow-globs = ["crypto/**/*.pl", "pregenerated/*.o"]' deny.toml \
  || fail 'ring bypass 必须只覆盖 38 Perl 与 17 .o 两族'

python3 -c '
import tomllib
d=tomllib.load(open("supply-chain/config.toml","rb"))
expected={
 "ipnet":"2.12.1","ring":"0.17.14","rustls":"0.23.43","rustls-pki-types":"1.15.1",
 "rustls-webpki":"0.103.15","tokio-rustls":"0.26.4","try-lock":"0.2.5","untrusted":"0.9.0",
 "want":"0.3.1","webpki-roots":"1.0.9","windows-sys":"0.52.0","windows-targets":"0.52.6",
 "windows_aarch64_gnullvm":"0.52.6","windows_aarch64_msvc":"0.52.6","windows_i686_gnu":"0.52.6",
 "windows_i686_gnullvm":"0.52.6","windows_i686_msvc":"0.52.6","windows_x86_64_gnu":"0.52.6",
 "windows_x86_64_gnullvm":"0.52.6","windows_x86_64_msvc":"0.52.6",
}
seen={}
for name,entries in d.get("exemptions",{}).items():
 for entry in entries:
  if "W-7 R29" in entry.get("notes",""):
   assert entry.get("criteria")=="safe-to-deploy",(name,entry)
   assert "owner=security" in entry["notes"] and "not a full source audit" in entry["notes"],(name,entry)
   assert name not in seen,name
   seen[name]=entry["version"]
assert seen==expected,(seen,expected)
' || fail 'W-7 Cargo Vet exemption 精确集合/owner/诚实说明漂移'

grep -qF '"CDLA-Permissive-2.0"' deny.toml || fail 'webpki-roots 数据许可未进白名单'
grep -qF 'e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8' NOTICE \
  || fail 'webpki-roots LICENSE 原件摘要未进 NOTICE'
python3 -c 'import json;d=json.load(open("provenance/sources.spdx.json"));m=[p for p in d["packages"] if p["SPDXID"]=="SPDXRef-Package-webpki-roots"];assert len(m)==1 and m[0]["versionInfo"]=="1.0.9" and m[0]["licenseConcluded"]=="CDLA-Permissive-2.0"' \
  || fail 'webpki-roots SPDX 登记漂移'

printf 'safe dialer dependency guard: ok (ring 0.17.14; 1044-line build.rs; 38 Perl; 17 objects; 20 explicit non-audit exemptions)\n'
