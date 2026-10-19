#!/usr/bin/env bash
# R230: protocol-only SDK graph and exact registry/macro source. No new audit exemption.
set -euo pipefail
metadata_file=$(mktemp)
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version 1 --locked --offline --all-features > "$metadata_file"
python3 - "$metadata_file" <<'PY'
import hashlib, json, pathlib, sys, tarfile, tomllib
root=pathlib.Path.cwd()
d=json.load(open(sys.argv[1]))
def require(condition, message):
    if not condition: raise SystemExit('Gateway SDK dependency guard: FAIL: '+message)
workspace=tomllib.loads((root/'Cargo.toml').read_text())['workspace']['dependencies']
sdk=workspace['acosmi-sdk']
require(sdk == {'version':'=5.0.0','default-features':False,'features':['custom-transport','sanitize']},'SDK declaration changed')
require(workspace['tokio-util']=={'version':'=0.7.19','default-features':False},'cancellation type direct edge changed')
infra=tomllib.loads((root/'crates/openbot-infra/Cargo.toml').read_text())
for dep in ['acosmi-sdk','tokio-util']:
    require(infra['dependencies'][dep]=={'workspace':True,'optional':True},'Infra optional edge changed: '+dep)
    require('dep:'+dep in infra['features']['server-runtime'],'runtime feature omitted: '+dep)
packages={p['id']:p for p in d['packages']};nodes={n['id']:n for n in d['resolve']['nodes']}
expected={
'acosmi-sdk':('5.0.0',360505,'4fbba2969b9ecf59906ae061e773ebe3d147d7a438b958693f5c76f29d708c50','16e94051dea41052858aa87cb815bb98d9a153d23eb869b2d01de54274c63c7f','0a2152f69019c92fae47d0bb905e3f83893574bc',False),
'async-stream':('0.3.6',13823,'0b5a71a6f37880a80d1d7f19efd781e4b5de42c88f0722cc13bcb6cc2cfe8476','157d381f6304eba77459fc10dfb5b1b22fc0d04e384a32865f32d8e67a34c0eb','b0b2f22df8e87b7fed7b2fa234509797adbff7db',False),
'async-stream-impl':('0.3.6',4312,'c7c24de15d275a1ecfd47a380fb4d5ec9bfe0933f309ed5e705b775596a3574d','157d381f6304eba77459fc10dfb5b1b22fc0d04e384a32865f32d8e67a34c0eb','b0b2f22df8e87b7fed7b2fa234509797adbff7db',True),
}
lock=tomllib.loads((root/'Cargo.lock').read_text())['package']
selected={}
for name,(version,size,digest,license_hash,commit,proc) in expected.items():
    found=[p for p in packages.values() if p['name']==name]
    require(len(found)==1 and found[0]['version']==version,'duplicate/unreviewed '+name)
    p=found[0];selected[name]=p
    require(p['source']=='registry+https://github.com/rust-lang/crates.io-index','registry origin: '+name)
    entry=[x for x in lock if x['name']==name]
    require(len(entry)==1 and entry[0]['checksum']==digest,'lock checksum: '+name)
    source=pathlib.Path(p['manifest_path']).parent
    archive=source.parent.parent.parent/'cache'/source.parent.name/(name+'-'+version+'.crate')
    raw=archive.read_bytes();require(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'official archive: '+name)
    manifest=tomllib.loads((source/'Cargo.toml').read_text())
    require(manifest['package'].get('build') is False and not (source/'build.rs').exists(),'build script: '+name)
    require(manifest.get('lib',{}).get('proc-macro',False)==proc,'proc-macro kind: '+name)
    require(p['license']=='MIT','license: '+name)
    require(hashlib.sha256((source/'LICENSE').read_bytes()).hexdigest()==license_hash,'license bytes: '+name)
    vcs=json.loads((source/'.cargo_vcs_info.json').read_text());require(vcs['git']['sha1']==commit,'VCS: '+name)
    require(vcs['git'].get('dirty')==(True if name=='async-stream' else None),'dirty metadata: '+name)
    # Exact pinned archive covers all macro templates and yielder unsafe source, not only names.
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path=pathlib.PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts,'archive path')
            if member.isdir(): continue
            require(member.isfile(),'archive link/special entry')
            relative=pathlib.Path(*path.parts[1:]);local=source/relative
            require(not local.is_symlink() and local.read_bytes()==tar.extractfile(member).read(),'source/cache drift: '+name+'/'+str(relative))
sdk_id=selected['acosmi-sdk']['id']
require(set(nodes[sdk_id]['features'])=={'custom-transport','sanitize'},'SDK optional network/default/loopback feature enabled')
parents={packages[n['id']]['name'] for n in nodes.values() if any(e['pkg']==sdk_id for e in n['deps'])}
require(parents=={'openbot-infra'},'SDK escaped sole Infra dependency boundary: '+str(parents))
def closure(start):
    seen=set();pending=[start]
    while pending:
        current=pending.pop()
        if current in seen: continue
        seen.add(current)
        for dep in nodes.get(current,{}).get('deps',[]):
            if any(k['kind'] in (None,'build') for k in dep['dep_kinds']):pending.append(dep['pkg'])
    return seen
names={packages[x]['name'] for x in closure(sdk_id)}
for forbidden in ['reqwest','hyper','hyper-util','hyper-rustls','rustls','native-tls','openssl','openssl-sys','tokio-tungstenite','tungstenite','aws-lc-rs','aws-lc-sys']:
    require(forbidden not in names,'SDK rebuilt HTTP/TLS/WS closure: '+forbidden)
ui=[p for p in packages.values() if p['name']=='openbot-ui']
require(len(ui)==1 and sdk_id not in closure(ui[0]['id']),'SDK reached UI normal/build graph')
allowed={root/'crates/openbot-infra/src/gateway_authority/enrollment.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/enrollment.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/enrollment/tests.rs',root/'crates/openbot-infra/src/gateway_transport.rs',root/'crates/openbot-infra/src/gateway_transport/framing.rs',root/'crates/openbot-infra/src/gateway_account.rs',root/'crates/openbot-infra/src/gateway_authority.rs',root/'crates/openbot-infra/src/gateway_authority/store.rs',root/'crates/openbot-infra/src/gateway_authority/strict.rs',root/'crates/openbot-infra/src/gateway_authorization.rs',root/'crates/openbot-infra/src/gateway_authorization/initial.rs',root/'crates/openbot-infra/src/gateway_authorization/reply.rs',root/'crates/openbot-infra/src/gateway_authorization/tokens.rs',root/'crates/openbot-infra/src/gateway_authorization/tests.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/registration.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/registration/tests.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/token.rs',root/'crates/openbot-infra/src/gateway_authorization/journal/token/tests.rs'}
for path in (root/'crates').glob('*/src/**/*.rs'):
    text=path.read_text()
    if 'acosmi::' in text:require(path in allowed,'SDK type escaped adapter: '+str(path.relative_to(root)))
    require('async_stream::__private' not in text,'first-party bypass of reviewed macro pair')
print('Gateway SDK dependency guard: PASS (exact 5.0.0, three fixed registry sources, macro bytes, sole Infra edge, no SDK HTTP/TLS/WS, no UI edge; no Vet/advisory/global-gate claim)')
PY
