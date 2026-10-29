#!/usr/bin/env bash
# G3 / R67：Axum typed WebSocket 的精确依赖、SHA-1 用途、unsafe/build.rs 与调用面 guard。
set -euo pipefail

fail() {
  printf 'websocket dependency guard: FAIL: %s\n' "$1" >&2
  exit 1
}

normal_tree=$(cargo tree -p openbot-server -e normal --prefix none --locked)
for exact in \
  'sha1 v0.10.7' \
  'tokio-tungstenite v0.29.0' \
  'tungstenite v0.29.0'; do
  grep -qxF "$exact" <<< "$normal_tree" || fail "依赖图缺少精确版本 $exact"
done
if grep -Eq '^(native-tls|tokio-native-tls) v' <<< "$normal_tree"; then
  fail 'thread WebSocket 图出现未授权 TLS/client 路径'
fi
feature_tree=$(cargo tree -p openbot-server -e features --prefix none --locked)
if grep -Eq '^tokio-tungstenite feature ".*tls' <<< "$feature_tree"; then
  fail 'tokio-tungstenite TLS feature 未经 delta audit'
fi

grep -qF 'axum = { version = "0.8.9", features = ["macros", "ws"] }' Cargo.toml \
  || fail 'Axum 版本或 ws feature 漂移'
expected_callers=$'crates/openbot-server/src/http/approvals.rs\ncrates/openbot-server/src/http/channels.rs\ncrates/openbot-server/src/http/screen.rs\ncrates/openbot-server/src/http/threads.rs'
[[ $(rg -l 'WebSocketUpgrade|drive_thread_websocket' crates --glob '*.rs' | sort) == \
   "$expected_callers" ]] \
  || fail 'WebSocket server 调用面越出 thread/channel/approval/screen typed transports'
if rg -n 'sha1::|Sha1' crates --glob '*.rs' --glob '!crates/omb-*/**'; then
  fail '第一方代码不得把 RFC6455 handshake SHA-1 复用为凭据/业务摘要'
fi
grep -qF 'const THREAD_EVENTS_WS_INPUT_LIMIT: usize = 1024;' \
  crates/openbot-server/src/http/threads.rs || fail 'WebSocket 1KiB inbound cap 漂移'
grep -qF 'OriginAuthenticated(auth): OriginAuthenticated' \
  crates/openbot-server/src/http/threads.rs || fail 'WebSocket trusted Origin extractor 缺失'
grep -qF 'super::realtime::close(&mut socket, stream, close_code::POLICY, "thread_events_read_only")' \
  crates/openbot-server/src/http/threads.rs || fail 'read-only 1008 close 边界缺失'
grep -qF 'const CHANNEL_ACTIVITY_INPUT_LIMIT: usize = 1024;' \
  crates/openbot-server/src/http/channels.rs || fail 'channel WebSocket 1KiB inbound cap 漂移'
grep -qF 'OriginAuthenticated(auth): OriginAuthenticated' \
  crates/openbot-server/src/http/channels.rs || fail 'channel WebSocket trusted Origin extractor 缺失'
grep -qF 'super::realtime::close(&mut socket, stream, close_code::POLICY, "channel_activity_read_only")' \
  crates/openbot-server/src/http/channels.rs || fail 'channel read-only 1008 close 边界缺失'
grep -qF 'const TOOL_APPROVAL_INPUT_LIMIT: usize = 1024;' \
  crates/openbot-server/src/http/approvals.rs || fail 'approval WebSocket 1KiB inbound cap 漂移'
grep -qF 'OriginAuthenticated(auth): OriginAuthenticated' \
  crates/openbot-server/src/http/approvals.rs || fail 'approval WebSocket trusted Origin extractor 缺失'
grep -qF 'super::realtime::close(&mut socket, stream, close_code::POLICY, "tool_approval_activity_read_only")' \
  crates/openbot-server/src/http/approvals.rs || fail 'approval read-only 1008 close 边界缺失'
grep -qF 'const SCREEN_WS_INPUT_LIMIT: usize = 1024;' \
  crates/openbot-server/src/http/screen.rs || fail 'screen WebSocket 1KiB inbound cap 漂移'
grep -qF 'bound: OriginBoundAuthenticated' \
  crates/openbot-server/src/http/screen.rs || fail 'screen exact verified Origin binding缺失'
grep -qF 'if uri.query().is_some()' \
  crates/openbot-server/src/http/screen.rs || fail 'screen ticket URL/query拒绝边界缺失'
grep -qF '.protocols([SCREEN_VIEWER_PROTOCOL])' \
  crates/openbot-server/src/http/screen.rs || fail 'screen upgrade base-only protocol选择漂移'
grep -qF '"screen_input_not_enabled"' \
  crates/openbot-server/src/http/screen.rs || fail 'screen read-only 1008 close边界缺失'
grep -qF '.write_buffer_size(0)' crates/openbot-server/src/http/screen.rs \
  || fail 'screen immediate write buffer边界缺失'
grep -qF '.max_write_buffer_size(SCREEN_VIEWER_MAX_BINARY_BYTES + SCREEN_WS_INPUT_LIMIT)' \
  crates/openbot-server/src/http/screen.rs || fail 'screen单帧write buffer上限漂移'
for reason in screen_idle screen_bandwidth screen_control_rate; do
  grep -qF "\"$reason\"" crates/openbot-server/src/http/screen.rs \
    || fail "screen transport budget关闭码缺失: $reason"
done
grep -qF 'timeout(limit, write)' crates/openbot-server/src/http/screen.rs \
  || fail 'screen write deadline缺失'

metadata=$(cargo metadata --format-version 1 --locked)
printf '%s' "$metadata" | python3 -c '
import json,os,re,sys,tomllib
d=json.load(sys.stdin)
expected={
 "sha1":("0.10.7","a978451301f4db1d02937a4ab3ccce137717b81826e79b7d49ffe3244a13c3b8",4),
 "tokio-tungstenite":("0.29.0","8f72a05e828585856dacd553fba484c242c46e391fb0e58917c942ee9202915c",0),
 "tungstenite":("0.29.0","6c01152af293afb9c7c2a57e4b559c5620b421f6d133261c60dd2d0cdb38e6b8",5),
}
packages={p["name"]:p for p in d["packages"] if p["name"] in expected}
assert set(packages)==set(expected),packages
lock=tomllib.load(open("Cargo.lock","rb"))
locked={(p["name"],p["version"]):p.get("checksum") for p in lock["package"]}
for name,(version,checksum,unsafe_expected) in expected.items():
 p=packages[name]
 assert p["version"]==version,(name,p["version"])
 assert locked[(name,version)]==checksum,(name,locked[(name,version)])
 root=os.path.dirname(p["manifest_path"])
 assert not os.path.exists(os.path.join(root,"build.rs")),(name,"build.rs")
 count=0
 for base,_,files in os.walk(os.path.join(root,"src")):
  for filename in files:
   if filename.endswith(".rs"):
    count += len(re.findall(r"\bunsafe\b",open(os.path.join(base,filename),encoding="utf-8").read()))
 assert count==unsafe_expected,(name,count,unsafe_expected)
config=tomllib.load(open("supply-chain/config.toml","rb"))
seen={}
for name,entries in config.get("exemptions",{}).items():
 for entry in entries:
  if "G3 R67" in entry.get("notes",""):
   assert entry.get("criteria")=="safe-to-deploy",(name,entry)
   assert "owner=security" in entry["notes"] and "not a full source audit" in entry["notes"],(name,entry)
   assert name not in seen,name
   seen[name]=entry["version"]
assert seen=={name:value[0] for name,value in expected.items()},seen
' || fail '锁文件/checksum/build.rs/unsafe/exemption 精确 delta 漂移'

printf 'websocket dependency guard: ok (4 typed server callers; 3 exact packages; build.rs=0; unsafe tokens=4/0/5; 3 explicit non-audit exemptions)\n'
