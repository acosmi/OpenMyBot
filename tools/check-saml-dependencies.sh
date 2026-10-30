#!/usr/bin/env bash
# W-7b / R50：samael/xmlsec/OpenSSL/libxml2 FFI、构建脚本、SAML profile 与 Cargo Vet guard。
set -euo pipefail

fail() {
  printf 'SAML dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

grep -qF 'samael = { version = "=0.0.22", default-features = false, features = ["xmlsec"] }' Cargo.toml \
  || fail 'samael 必须精确钉 0.0.22 且显式开启 xmlsec'

tree=$(cargo tree -p openbot-infra -e all --prefix none --locked | sed -E 's/ \(proc-macro\)$//; s/ \(\*\)$//' | sort -u)
for exact in \
  'adler2 v2.0.1' 'bindgen v0.72.1' 'cexpr v0.6.0' 'clang-sys v1.9.1' \
  'crc32fast v1.5.1' 'darling v0.20.11' 'darling_core v0.20.11' \
  'darling_macro v0.20.11' 'data-encoding v2.11.1' 'derive_builder v0.20.2' \
  'derive_builder_core v0.20.2' 'derive_builder_macro v0.20.2' 'flate2 v1.1.9' \
  'fnv v1.0.7' 'foreign-types v0.3.2' 'foreign-types-shared v0.1.1' \
  'glob v0.3.4' 'libloading v0.8.9' 'libxml v0.3.3' 'miniz_oxide v0.8.9' \
  'openssl v0.10.81' 'openssl-macros v0.1.1' 'openssl-probe v0.1.6' \
  'openssl-sys v0.9.117' 'pkg-config v0.3.34' 'prettyplease v0.2.37' \
  'quick-xml v0.41.0' 'samael v0.0.22' 'shlex v1.3.0' \
  'simd-adler32 v0.3.10' 'vcpkg v0.2.15'; do
  grep -qxF "$exact" <<< "$tree" || fail "依赖图缺少精确版本 $exact"
done

feature_tree=$(cargo tree -p openbot-infra -e features --prefix none --locked | sed -E 's/ \(\*\)$//' | sort -u)
grep -qxF 'samael feature "xmlsec"' <<< "$feature_tree" \
  || fail 'samael xmlsec feature 未生效'

metadata=$(cargo metadata --format-version 1 --locked)
printf '%s' "$metadata" | python3 -c '
import hashlib,json,sys
d=json.load(sys.stdin)
expected={
 "bindgen":("0.72.1",29,"f7a10af0a21662e104e0058da7e3471a20be328eef6c7c41988525be90fdfe92"),
 "clang-sys":("1.9.1",53,"1d3a13cba52050a62c1d420431d2c8dd2f96919e1b4a6cc7faf13a84d807838b"),
 "crc32fast":("1.5.1",35,"deb6052c4a586e8875ef677fe2d9e9dcfafebfa949803455ea8eff6e7dbde436"),
 "libxml":("0.3.3",60,"8541d3886b77064f5ea766010c7b1db3603a4b0d9488d49d53b0d9c3f7daaed1"),
 "openssl":("0.10.81",167,"ee2656bba4668b5850a6ff638a56910dbc555c0f1e574c3b4210a45a3ea98382"),
 "openssl-sys":("0.9.117",551,"3a7f63b3c446451801ac03c34e03051b8d3ebcceea28b8fb2688922255629d27"),
 "prettyplease":("0.2.37",21,"79a5b2d260aa97aeac7105fbfa00774982f825cd708c100ea96d01c39974bb88"),
 "samael":("0.0.22",88,"f83b4cd2151cdee8356812427dd27f279ee5fd9e36bddab2c97f6bbd85ebb8cc"),
}
seen={}
for p in d["packages"]:
 if p["name"] not in expected: continue
 builds=[t["src_path"] for t in p["targets"] if "custom-build" in t["kind"]]
 assert len(builds)==1,(p["name"],builds)
 b=open(builds[0],"rb").read()
 seen[p["name"]]=(p["version"],len(b.splitlines()),hashlib.sha256(b).hexdigest())
assert seen==expected,(seen,expected)
' || fail '8 份 build.rs 精确版本/行数/SHA 漂移'

for crate in bindgen clang-sys crc32fast libxml openssl openssl-sys prettyplease samael; do
  grep -qF "\"$crate\"" deny.toml || fail "deny.toml 未放行已审 build.rs: $crate"
done
grep -qF 'crate = "samael@0.0.22"' deny.toml || fail '缺 samael 精确版本 executable bypass'
grep -qF 'allow-globs = ["test_vectors/multi_saml_response.sh"]' deny.toml \
  || fail 'samael bypass 必须只覆盖唯一测试向量生成脚本'

samael_manifest=$(printf '%s' "$metadata" | python3 -c 'import json,sys;d=json.load(sys.stdin);m=[p["manifest_path"] for p in d["packages"] if p["name"]=="samael" and p["version"]=="0.0.22"];assert len(m)==1,m;print(m[0])')
samael_dir=${samael_manifest%/Cargo.toml}
vector_script="$samael_dir/test_vectors/multi_saml_response.sh"
[[ "$(shasum -a 256 "$vector_script" | awk '{print $1}')" == 'ab091e9a22bc13290acfc03ad2b7ff372465d8e8926330cfa1e56d4d57ccfd2f' ]] \
  || fail 'samael 唯一 executable script hash 漂移'
if rg -q 'multi_saml_response\.sh' "$samael_dir/bindings.rs" "$samael_dir/src" --glob '*.rs'; then
  fail 'samael 测试向量脚本进入 build/production 调用面'
fi

python3 -c '
import tomllib
d=tomllib.load(open("supply-chain/config.toml","rb"))
expected={
 "adler2":"2.0.1","bindgen":"0.72.1","cexpr":"0.6.0","clang-sys":"1.9.1",
 "crc32fast":"1.5.1","darling":"0.20.11","darling_core":"0.20.11",
 "darling_macro":"0.20.11","data-encoding":"2.11.1","derive_builder":"0.20.2",
 "derive_builder_core":"0.20.2","derive_builder_macro":"0.20.2","flate2":"1.1.9",
 "fnv":"1.0.7","foreign-types":"0.3.2","foreign-types-shared":"0.1.1",
 "glob":"0.3.4","libloading":"0.8.9","libxml":"0.3.3","miniz_oxide":"0.8.9",
 "openssl":"0.10.81","openssl-probe":"0.1.6","openssl-sys":"0.9.117",
 "pkg-config":"0.3.34","prettyplease":"0.2.37","quick-xml":"0.41.0",
 "samael":"0.0.22","shlex":"1.3.0","simd-adler32":"0.3.10","vcpkg":"0.2.15",
}
seen={}
for name,entries in d.get("exemptions",{}).items():
 for entry in entries:
  if "W-7b R50" in entry.get("notes",""):
   assert entry.get("criteria")=="safe-to-deploy",(name,entry)
   assert "owner=security" in entry["notes"] and "not a full source audit" in entry["notes"],(name,entry)
   assert name not in seen,name
   seen[name]=entry["version"]
assert seen==expected,(seen,expected)
' || fail '30 条 W-7b Cargo Vet exemption 集合/owner/诚实说明漂移'

saml_source='crates/openbot-infra/src/auth/sso/saml.rs'
grep -qF 'ReduceMode::ValidateAndMarkNoAncestors' "$saml_source" \
  || fail 'SAML 未固定 XSW-resistant signed-root reduction'
grep -qF 'xml.contains("<!DOCTYPE")' "$saml_source" || fail 'SAML 未拒绝 DOCTYPE'
grep -qF 'xml.contains("<!ENTITY")' "$saml_source" || fail 'SAML 未拒绝 ENTITY'
grep -qF 'AllowedSignatureAlgorithm::RsaSha256' "$saml_source" || fail 'SAML SHA-2 allowlist 缺正向算法'
grep -qF 'const ALLOWED_DIGEST_ALGORITHMS: &[&str]' "$saml_source" \
  || fail 'SAML DigestMethod 未使用封闭 SHA-2 allowlist'
grep -qF 'transform_algorithms[0] != ENVELOPED_SIGNATURE' "$saml_source" \
  || fail 'SAML Reference transforms 未锁 enveloped-signature + exclusive-c14n'
if sed -n '/const ALLOWED_SIGNATURE_ALGORITHMS/,/^];/p' "$saml_source" | grep -Eq 'Sha1|Sha224|Dsa'; then
  fail 'SAML 签名 allowlist 出现 SHA-1/SHA-224/DSA'
fi
grep -qF '.all(|restriction|' "$saml_source" || fail '多 AudienceRestriction 未按 AND 语义校验'
grep -qF 'const MAX_ASSERTION_LIFETIME: Duration = Duration::minutes(10);' "$saml_source" \
  || fail 'SAML assertion 最大有效期未锁为 10 分钟'
grep -qF 'const MAX_GROUP_CLAIM_VALUES: usize = 256;' "$saml_source" \
  || fail 'SAML group claim 数量上限漂移或消失'
grep -qF 'validate_saml_entity_id(&input.issuer)?;' crates/openbot-infra/src/auth/sso/config.rs \
  || fail 'SAML EntityID 被错误套用 OIDC HTTPS issuer 规则'
grep -qF 'Ok(effective_expiry + MAX_CLOCK_SKEW)' "$saml_source" \
  || fail 'SAML replay expiry 未覆盖 verifier 接受的 clock-skew 尾窗'
ephemeral_source='crates/openbot-infra/src/auth/sso/ephemeral.rs'
grep -qF 'const MAX_ASSERTION_REPLAY_RETENTION: Duration = Duration::minutes(14);' "$ephemeral_source" \
  || fail 'SAML replay store 未锁 10 分钟 assertion + 双向 clock-skew 上界'
if rg -q 'assertion_expires_at\.min\(' "$ephemeral_source"; then
  fail 'SAML replay 行被提前截短，可能在 assertion 仍有效时消失'
fi
if rg -q 'openssl::(ssl|ocsp|pkcs12|quic)' crates --glob '*.rs'; then
  fail 'OpenSSL 3.6.3 的未修 QUIC/OCSP 低危 advisory 前提进入本仓调用面'
fi

vault_users=$(rg -l 'SsoConfigVault' crates --glob '*.rs' | sort)
expected_vault_users=$'crates/openbot-infra/src/auth/sso/service.rs\ncrates/openbot-infra/src/auth/sso/store.rs\ncrates/openbot-infra/src/auth/sso/vault.rs'
[[ "$vault_users" == "$expected_vault_users" ]] \
  || fail 'SSO config vault 逃出显式 service/store/vault 边界，可能重新变成全局 model hook'
grep -qF 'pub(crate) struct SsoConfigVault' crates/openbot-infra/src/auth/sso/vault.rs \
  || fail 'SSO config vault 可见性不再局限于 infra crate'
grep -qF 'pub(crate) enum SsoSecretColumn' crates/openbot-infra/src/auth/sso/vault.rs \
  || fail 'SSO config vault 列名不再由 OIDC/SAML 封闭枚举承载'
store_source='crates/openbot-infra/src/auth/sso/store.rs'
grep -qF 'assert_deployment_owned_row(row)?;' "$store_source" \
  || fail '历史 organization-scoped provider 可能被放大成 deployment-owned'
grep -qF 'let canonical_domain = domains_column(&domains);' "$store_source" \
  || fail '历史 domain 未在读迁移中收敛到 canonical 列值'

for hash in \
  0544f2095045dd6f52fff94000333399cd4fe2dcd6a50659a0a55e4d2b543334 \
  5d4873884a890122a4b9b20ad56ac6f7da1d796a5bfcf04a427970ac96217626 \
  a6d217151f3d423e06639c075bad8e442ea1936828d3a660105122ef78ecd96d \
  7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a; do
  grep -qF "$hash" NOTICE || fail "SAML native license 原件摘要未进 NOTICE: $hash"
done
python3 -c '
import json
d=json.load(open("provenance/sources.spdx.json"))
expected={
 "SPDXRef-Package-samael":("0.0.22","MIT"),
 "SPDXRef-Package-libxml2-native":("2.15.3","MIT"),
 "SPDXRef-Package-xmlsec-native":("1.3.12","MIT"),
 "SPDXRef-Package-openssl-native":("3.6.3","Apache-2.0"),
 "SPDXRef-Package-openai-dotnet-recorded-trace":("19d0a3cb8e0cf0f3137a5c56c3c70a0c3f6c96f5","MIT"),
}
seen={p["SPDXID"]:(p.get("versionInfo"),p.get("licenseConcluded")) for p in d["packages"] if p["SPDXID"] in expected}
assert seen==expected,(seen,expected)
ids=[p["SPDXID"] for p in d["packages"]]
assert len(d["packages"])==62 and len(ids)==len(set(ids)),(len(d["packages"]),len(set(ids)))
' || fail 'SAML/native SPDX package 集合、版本、许可或总数漂移'

case "$(uname -s)" in
  Darwin)
    command -v xmlsec1-config >/dev/null || fail 'macOS 缺 xmlsec1-config（brew install libxmlsec1）'
    [[ "$(xmlsec1-config --version)" == '1.3.12' ]] \
      || fail "macOS xmlsec1 版本漂移：$(xmlsec1-config --version)"
    if [[ "$(uname -m)" == 'arm64' ]]; then
      grep -qF 'native=/opt/homebrew/opt/libxml2/lib' .cargo/config.toml \
        || fail 'Apple Silicon 未锁单一 Homebrew libxml2 链接路径'
      pc='/opt/homebrew/opt/libxmlsec1/lib/pkgconfig:/opt/homebrew/opt/libxml2/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig'
      [[ "$(PKG_CONFIG_PATH="$pc" pkg-config --modversion libxml-2.0)" == '2.15.3' ]] \
        || fail 'Homebrew libxml2 版本漂移'
      [[ "$(PKG_CONFIG_PATH="$pc" pkg-config --modversion openssl)" == '3.6.3' ]] \
        || fail 'Homebrew OpenSSL 版本漂移'
    elif [[ "$(uname -m)" == 'x86_64' ]]; then
      grep -qF 'native=/usr/local/opt/libxml2/lib' .cargo/config.toml \
        || fail 'Intel macOS 未锁单一 Homebrew libxml2 链接路径'
      pc='/usr/local/opt/libxmlsec1/lib/pkgconfig:/usr/local/opt/libxml2/lib/pkgconfig:/usr/local/opt/openssl@3/lib/pkgconfig'
      [[ "$(PKG_CONFIG_PATH="$pc" pkg-config --modversion libxml-2.0)" == '2.15.3' ]] \
        || fail 'Intel Homebrew libxml2 版本漂移'
      [[ "$(PKG_CONFIG_PATH="$pc" pkg-config --modversion openssl)" == '3.6.3' ]] \
        || fail 'Intel Homebrew OpenSSL 版本漂移'
    else
      fail "未审计的 macOS 架构：$(uname -m)"
    fi
    ;;
  Linux)
    command -v xmlsec1-config >/dev/null || fail 'Linux 缺 xmlsec1-config/libxmlsec1-dev'
    pkg-config --exists xmlsec1 libxml-2.0 openssl || fail 'Linux xmlsec/libxml2/OpenSSL pkg-config 闭包不完整'
    ;;
  *) fail 'samael/xmlsec 生产构建当前只审计 Linux/macOS；不得静默关闭 SAML' ;;
esac

bindings=$(find target/debug/build -path '*samael-*/out/xmlsec_bindings.rs' -type f -print | head -n1 || true)
if [[ -n "$bindings" ]]; then
  lines=$(wc -l < "$bindings" | tr -d ' ')
  (( lines >= 40000 )) || fail "生成的 xmlsec bindings 异常过小：$lines 行"
fi

printf 'SAML dependency guard: ok (samael 0.0.22; 31-crate delta; 8 build scripts; 30 explicit non-audit exemptions)\n'
