#!/usr/bin/env bash
# G4 Batch 12/102/103: MCP OAuth must stay on per-server SafeDialer authority, exact
# issuer/resource, R395 durable send ownership, R397 one-POST refresh, local-first revocation
# and retained compensation.
set -euo pipefail

fail() {
  printf 'MCP OAuth runtime guard: FAIL: %s\n' "$1" >&2
  exit 1
}

files=(
  crates/openbot-infra/src/mcp_oauth.rs
  crates/openbot-infra/src/mcp_connections.rs
  crates/openbot-infra/src/mcp_credentials.rs
  crates/openbot-infra/src/google_drive_oauth.rs
  crates/openbot-infra/src/store/plugin_user_credential.rs
  crates/openbot-infra/src/store/plugin_user_credential/refresh_operation.rs
)

if rg -n 'reqwest|hyper::|TcpStream|lookup_host|Command::new|std::process' "${files[@]}"; then
  fail 'OAuth/credential code bypasses the unique SafeDialer or starts a process'
fi
grep -qF 'SafeHttpRequest::mcp(' crates/openbot-infra/src/mcp_oauth.rs \
  || fail '401 protected-resource probe no longer uses bounded SafeDialer MCP request'
grep -qF 'bearer_parameter(challenge, "resource_metadata")' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'WWW-Authenticate resource_metadata priority disappeared'
grep -qF 'serializer.append_pair("resource", resource);' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'authorization/code token resource binding disappeared'
grep -qF 'serializer.append_pair("resource", discovery.resource());' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'refresh token resource binding disappeared'
grep -qF 'code_challenge_method", "S256"' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'PKCE S256 authorization binding disappeared'
grep -qF 'metadata.issuer != client.issuer' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'authorization-server exact issuer validation disappeared'
grep -qF 'dialer: self.dialer.with_egress_policy(EgressPolicy::new(allowlist))' \
  crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'MCP OAuth no longer clones the shared dialer with exact per-server egress authority'
[[ $(grep -c '\.with_egress_allowlist' crates/openbot-infra/src/mcp_connections.rs) -eq 4 ]] \
  || fail 'register/begin/code/revoke do not all consume per-server OAuth egress authority'
grep -qF 'self.with_egress_allowlist(request.egress_allowlist().clone())' \
  crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'runtime refresh rotation lost its selected server egress authority'
grep -qF 'coalesce(s.egress_allow_cidrs,ARRAY[]::text[]) AS egress_allow_cidrs' \
  crates/openbot-infra/src/store/plugin_user_credential.rs \
  || fail 'runtime credential selection no longer carries current server egress authority'
grep -qF "coalesce(s.transport,'mcp') AS server_transport" \
  crates/openbot-infra/src/store/plugin_user_credential.rs \
  || fail 'runtime credential selection no longer binds the closed vendor transport'
refresh_store=crates/openbot-infra/src/store/plugin_user_credential.rs
refresh_operation=crates/openbot-infra/src/store/plugin_user_credential/refresh_operation.rs
grep -qF 'FOR SHARE OF owner,s,d,uc FOR UPDATE OF c' "$refresh_operation" \
  || fail 'refresh claim/admission/completion no longer lock actor/server/client/connection/credential authority'
for anchor in \
  'AND c.encrypted_value=$4 AND c.revoked_at IS NULL' \
  'AND d.id=$5 AND d.encrypted_value=$6 AND d.revoked_at IS NULL' \
  'coalesce(s.credential_generation,0)=$10 AND s.updated_at=$11 AND d.updated_at=$12' \
  'coalesce(owner.auth_generation,0)=$13 AND uc.scope=$14' \
  'EXISTS(SELECT 1 FROM public.user_roles ur WHERE ur.user_id=owner.id)' \
  'NOT EXISTS(SELECT 1 FROM public.revoked_access ra WHERE ra.email=lower(owner.email))'; do
  grep -qF "$anchor" "$refresh_operation" \
    || fail "refresh operation lost a current authority binding: $anchor"
done
for anchor in \
  'CREATE TABLE public.oauth_refresh_operations (' \
  'UNIQUE (credential_id,generation)' \
  "ON public.oauth_refresh_operations(credential_id) WHERE state <> 'committed'"; do
  grep -qF "$anchor" crates/openbot-infra/sql/native_0034.sql \
    || fail "durable OAuth send-ownership schema disappeared: $anchor"
done
grep -qF 'mod refresh_operation;' "$refresh_store" \
  || fail 'durable OAuth refresh store is no longer assembled'
grep -qF '.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)' "$refresh_operation" \
  || fail 'private OAuth send admission is no longer single-use'
grep -qF "AND state='pending' AND admitted_at IS NULL" "$refresh_operation" \
  || fail 'token send admission lost its persistent one-use CAS'
grep -qF "AND state='committed' AND admitted_at IS NOT NULL" "$refresh_operation" \
  || fail 'uncertain COMMIT no longer reads the exact committed operation receipt'
grep -qF "WHERE operation_id=\$1 AND state='pending' AND admitted_at IS NOT NULL" "$refresh_operation" \
  || fail 'failed token exchange no longer retains its unresolved operation'
grep -qF 'UserCredentialSelectionError::RotationPending' "$refresh_operation" \
  || fail 'a pre-existing unresolved refresh operation is no longer refused'

# These anchors complement the real PG race/lost-COMMIT tests: a helper existing in an unused
# module must not satisfy the guard. Check its actual caller order and both token-send adapters.
python3 - <<'PY' || fail 'OAuth claim/admission/completion caller ordering drifted'
from pathlib import Path
import re
store = Path('crates/openbot-infra/src/store/plugin_user_credential.rs').read_text()
operation = Path('crates/openbot-infra/src/store/plugin_user_credential/refresh_operation.rs').read_text()
broker = Path('crates/openbot-infra/src/mcp_credentials.rs').read_text()
public_fresh = store.split('pub async fn fresh_user_access_token<', 1)[1].split('pub(crate) async fn fresh_user_access_token_admitted<', 1)[0]
assert public_fresh.index('.admission(') < public_fresh.index('.fresh_user_access_token_admitted('), 'public refresh must acquire admission before forwarding'
assert public_fresh.count('.fresh_user_access_token_admitted(') == 1, 'public refresh must forward once'
fresh = store.split('pub(crate) async fn fresh_user_access_token_admitted<', 1)[1].split('pub async fn connections_for', 1)[0]
anchors = ['.prepare_admitted(server_id, actor, admission)', 'current(admission)',
           '.claim_refresh(&prepared, admission)', 'OperationSendFence::new',
           'prepared.exchange_rotating(exchanger, &fence)', 'fence.admitted()',
           '.finish_refresh(', 'Ok(VendorAccessToken(grant.access_token))']
positions = [fresh.index(anchor) for anchor in anchors]
assert positions == sorted(positions), 'access release moved before confirmed operation completion'
assert operation.count('lock_binding(') == 5, 'claim/admission/complete/readback must each recheck current authority'
for start, end in [('pub(super) async fn claim_refresh', 'async fn admit_refresh'),
                   ('async fn admit_refresh', 'pub(super) async fn fail_refresh')]:
    body = operation.split(start, 1)[1].split(end, 1)[0]
    commit = re.search(r'tx\.commit\(\)\s*\.await', body)
    assert commit is not None and body.index('lock_binding(') < commit.start(), start
assert 'pub async fn exchange<' not in store, 'legacy prepared exchange can bypass durable ownership'
refresh = broker.split('async fn refresh_actor_bearer', 1)[1].split('impl core::fmt::Debug', 1)[0]
assert refresh.count('.fresh_user_access_token_admitted(') == 1, 'broker must invoke exactly one owned refresh under its held admission'
assert 'for attempt' not in refresh and 'continue;' not in refresh and 'loop {' not in refresh, 'broker retry can duplicate refresh sends'
mcp_source = Path('crates/openbot-infra/src/mcp_oauth.rs').read_text()
drive_source = Path('crates/openbot-infra/src/google_drive_oauth.rs').read_text()
mcp = mcp_source.split('async fn refresh(', 1)[1].split('impl RotatingOAuthTokenExchanger', 1)[0]
drive = drive_source.split('impl RotatingOAuthTokenExchanger', 1)[1].split('struct StoredGoogleClient', 1)[0]
for label, source, body in [('MCP', mcp_source, mcp), ('Drive', drive_source, drive)]:
    anchors = ['SafeHttpRequest::oauth_refresh_form(', '.admit_token_send()',
               '.execute(plan)', 'if status.is_redirection()', 'if !status.is_success()']
    positions = [body.index(anchor) for anchor in anchors]
    assert positions == sorted(positions), f'{label} must fix no-redirect policy before admission and reject 3xx before token/error parsing'
    assert body.count('.execute(plan)') == 1, f'{label} refresh must have exactly one owned execute'
    assert source.count('SafeHttpRequest::oauth_refresh_form(') == 1, f'{label} no-redirect policy must stay scoped to refresh'
    redirection = body.split('if status.is_redirection()', 1)[1].split('if !status.is_success()', 1)[0]
    assert '::Unavailable)' in redirection, f'{label} redirect must retain unresolved state'
assert 'self.token_request(body)' not in drive, 'Drive refresh must not use the redirect-enabled code exchange helper'
safe = Path('crates/openbot-infra/src/net/safe_http.rs').read_text()
refresh_plan = safe.split('pub(crate) fn oauth_refresh_form(', 1)[1].split('pub fn post_json(', 1)[0]
assert 'Self::post_form_with_scheme(' in refresh_plan and 'request.follow_redirects = false;' in refresh_plan, 'dedicated refresh form must disable redirects'
default_form = safe.split('pub(crate) fn post_form_with_scheme(', 1)[1].split('pub(crate) fn oauth_refresh_form(', 1)[0]
assert 'follow_redirects: true' in default_form, 'unrelated form requests must retain their default redirect policy'
assert '!request.follow_redirects || !is_redirect(raw.status)' in safe, 'transport must return the first refresh response without a second hop'
tests = Path('crates/openbot-infra/tests/oauth_refresh_redirect.rs').read_text()
for adapter in ('mcp', 'drive'):
    for status in (303, 307, 308):
        assert f'{adapter}_refresh_{status}_sends_once_and_stays_unknown' in tests, 'real adapter redirect regression matrix disappeared'
PY
grep -qF 'if request.transport() != "mcp"' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'generic MCP refresh accepted another vendor transport'
grep -qF '|| request.transport() != "google_drive_rest"' \
  crates/openbot-infra/src/google_drive_oauth.rs \
  || fail 'curated Drive refresh accepted another vendor transport'
grep -qF '|| !request.egress_allowlist().is_empty()' \
  crates/openbot-infra/src/google_drive_oauth.rs \
  || fail 'curated Google Drive OAuth accepted an MCP private-egress override'

grep -qF 'openbot-mcp-oauth-state-v1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth state HMAC purpose separation disappeared'
grep -qF 'openbot-mcp-oauth-attempt-aead-v1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth attempt AEAD purpose separation disappeared'
grep -qF 'DELETE FROM public.verifications WHERE identifier=$1' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'callback no longer burns state before validation/network'
grep -qF "FOR UPDATE SKIP LOCKED" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'pending vendor revocation is no longer multi-replica claimed'
grep -qF "'revocation_status','pending'" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'local-first disconnect tombstone disappeared'
grep -qF 'const ATTEMPT_VERSION: u8 = 3;' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'sealed OAuth attempt no longer binds the v3 egress authority shape'
grep -qF 'material.egress_allow_cidrs != attempt.egress_allow_cidrs' \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'OAuth callback no longer rejects egress authority drift before token exchange'
grep -qF 'validate_stored_client' crates/openbot-infra/src/mcp_oauth.rs \
  || fail 'admin removal no longer validates retained OAuth client material without network'
grep -qF 'struct RemovedServerRevocationContext' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'versioned admin-removal revocation context disappeared'
grep -qF 'removed_server_client_material' crates/openbot-infra/src/mcp_connections.rs \
  || fail 'admin removal no longer reloads its exact retained client/context'
grep -qF 'let (refresh, material) = if removed_server || admin_retirement {' \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'server removal and admin retirement no longer use their retained credential context'
rg -Uq '\.removed_server_client_material\(\s*&claim,\s*admin_retirement,\s*admission\.restore_cohort\(\),\s*deadline,\s*\)' \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'removed-server claim no longer routes through its retained context'
if grep -qF 'let material = if removed_server' crates/openbot-infra/src/mcp_connections.rs; then
  fail 'removed-server tombstones can fall back to a re-added same-id server'
fi
grep -qF "'revocation_status','operator_required'" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'irrecoverable retained revocation material no longer exits the retry loop'
grep -qF "metadata=metadata-'server_removal_revocation'" \
  crates/openbot-infra/src/mcp_connections.rs \
  || fail 'successful user-token revoke no longer scrubs retained network context'
grep -qF "split_part(g.ref,'/',1)=\$1" crates/openbot-infra/src/mcp_connections.rs \
  || fail 'admin removal no longer deletes stale/orphan grants by exact server prefix'
grep -qF '### MCP credential revocation recovery' README.md \
  || fail 'admin-removal vendor compensation runbook disappeared'
grep -qF 'operator_required' README.md \
  || fail 'admin-removal compensation runbook lost its operator-required recovery boundary'

grep -qF 'ADD COLUMN credential_generation bigint' crates/openbot-infra/sql/native_0018.sql \
  || fail 'credential generation migration disappeared'
grep -qF 'g.credential_generation=coalesce(s.credential_generation,0)' crates/openbot-infra/src/mcp_catalog.rs \
  || fail 'grant visibility no longer binds deployment credential generation'
grep -qF 'outcome == Err(McpClientError::AuthRequired)' crates/openbot-infra/src/agent_tools.rs \
  || fail 'controlled OAuth 401 refresh/retry branch disappeared'

authorization_slice=$(sed -n '/pub async fn authorization_plan/,/pub async fn exchange_authorization_code/p' crates/openbot-infra/src/mcp_oauth.rs)
if rg -n 'append_pair\("(access_token|refresh_token|client_secret)"' <<< "$authorization_slice"; then
  fail 'a credential was added to an authorization URL query'
fi
grep -qF '.field("client_secret", &"[redacted]")' crates/openbot-contracts/src/mcp.rs \
  || fail 'admin OAuth client Debug redaction disappeared'

printf 'MCP OAuth runtime guard: ok (per-server egress + durable claim/admission/receipt + no-redirect refresh; SafeDialer PRM/issuer/resource; HMAC+AEAD state v3; credential generation; local-first + admin-removal compensation)\n'
