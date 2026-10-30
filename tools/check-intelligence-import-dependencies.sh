#!/usr/bin/env bash
# G3/G8 / R68：Intelligence importer crypto、唯一调用面与 runtime exclusion guard。
set -euo pipefail

fail() {
  printf 'intelligence import dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

tree=$(cargo tree -p openbot-server -e all --prefix none --locked)
for exact in \
  'aes-gcm v0.10.3' \
  'base64 v0.22.1' \
  'ed25519-dalek v2.2.0' \
  'hkdf v0.12.4' \
  'sha2 v0.10.9'; do
  grep -qxF "$exact" <<< "$tree" || fail "依赖图缺少精确版本 $exact"
done

callers=$(rg -l 'IntelligenceBundleDecryptionKey|verify_intelligence_bundle|PostgresIntelligenceImportStore' \
  crates/*/src --glob '*.rs' | sort)
# 测试夹具：auth/thread_history_management_tests.rs 只经 auth.rs 的 #[cfg(test)] mod 编入（PR #181）。
expected=$'crates/openbot-infra/src/intelligence_bundle.rs\ncrates/openbot-infra/src/intelligence_import.rs\ncrates/openbot-server/src/auth/thread_history_management_tests.rs\ncrates/openbot-server/src/bin/openbot-migrate.rs'
[[ "$callers" == "$expected" ]] || fail "importer 调用面越出 one-shot migration path：[$callers]"
if rg -n 'intelligence_(bundle|import)|IntelligenceImport' crates/openbot-server/src/main.rs; then
  fail '最终 Server runtime main 不得持有 Intelligence importer/client'
fi
grep -qF 'pub const MAX_INTELLIGENCE_BUNDLE_BYTES: usize = 512 * 1024 * 1024;' \
  crates/openbot-infra/src/intelligence_bundle.rs || fail 'bundle size cap 漂移'
grep -qF 'Hkdf::<Sha256>::new(Some(payload_hash), master)' \
  crates/openbot-infra/src/intelligence_bundle.rs || fail 'per-payload HKDF key derivation 缺失'
grep -qF '.verify_strict(&signed, &signature)' \
  crates/openbot-infra/src/intelligence_bundle.rs || fail 'Ed25519 strict verification 缺失'
grep -qF 'metadata.mode() & 0o077 != 0' \
  crates/openbot-server/src/bin/openbot-migrate.rs || fail 'Unix secret key file private-mode guard 缺失'

python3 -c '
import tomllib
d=tomllib.load(open("Cargo.lock","rb"))
expected={
 ("aes-gcm","0.10.3"):"831010a0f742e1209b3bcea8fab6a8e149051ba6099432c8cb2cc117dec3ead1",
 ("base64","0.22.1"):"72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6",
 ("ed25519-dalek","2.2.0"):"70e796c081cee67dc755e1a36a0a172b897fab85fc3f6bc48307991f64e4eca9",
 ("hkdf","0.12.4"):"7b5f8eb2ad728638ea2c7d47a21db23b7b58a72ed6a38256b8a1849f15fbbdf7",
 ("sha2","0.10.9"):"a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283",
}
seen={(p["name"],p["version"]):p.get("checksum") for p in d["package"] if (p["name"],p["version"]) in expected}
assert seen==expected,(seen,expected)
' || fail 'import crypto lock checksum 漂移'

printf 'intelligence import dependency guard: ok (AES-256-GCM + HKDF-SHA256 + Ed25519; one-shot CLI only; exact lock checksums)\n'
