#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# RUSTSEC-2023-0071 只涉及可被网络观测的 RSA 私钥运算。本仓豁免的前提是只用
# openidconnect 的 RP 公钥验签路径；下列任一符号出现都代表前提变了，必须先重审。
private_key_pattern='\b(RsaPrivateKey|CoreRsaPrivateSigningKey|PrivateSigningKey|private_key_jwt)\b'

# 正向对照：证明扫描器和 pattern 本轮确实说得出“命中”。
rg -q "$private_key_pattern" <<< 'CoreRsaPrivateSigningKey'

if rg -n "$private_key_pattern" crates --glob '*.rs'; then
  printf '%s\n' 'RUSTSEC-2023-0071 豁免失效：仓内出现 RSA 私钥/私签路径，必须重新可达性审查。' >&2
  exit 1
fi

actual="$(cargo tree --workspace --exclude 'omb-*' -i rsa -e normal --all-features --prefix depth --charset ascii \
  | awk '{name=$1; sub(/^[0-9]+/, "", name); print name " " $2}')"
expected='rsa v0.9.10
openidconnect v4.0.1
openbot-infra v0.0.0
openbot-desktop v0.0.0
openbot-server v0.0.0'

if [[ "$actual" != "$expected" ]]; then
  printf '%s\n' 'RUSTSEC-2023-0071 豁免失效：RSA 版本或反向生产依赖链已变，必须重新审查。' >&2
  printf '%s\n' "$actual" >&2
  exit 1
fi

enabled_openid_features="$(cargo tree -i openidconnect -e features --all-features \
  --prefix depth --charset ascii | rg '^[0-9]+openidconnect feature' || true)"
if [[ -n "$enabled_openid_features" ]]; then
  printf '%s\n' 'RUSTSEC-2023-0071 豁免失效：openidconnect feature 图已扩大，必须重新审查。' >&2
  printf '%s\n' "$enabled_openid_features" >&2
  exit 1
fi

printf '%s\n' 'RUSTSEC-2023-0071 waiver guard: ok (public-key verification only; graph unchanged)'
