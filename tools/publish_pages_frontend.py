"""Publish only the reviewed frontend manifest onto remote main; no local staging."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
REPO='kakyung98/ics-vex-dashboard'


def api(path,method='GET',data=None):
    command=['gh','api','--method',method,f'repos/{REPO}/{path}']
    if data is not None:command+=['--input','-']
    result=subprocess.run(command,input=json.dumps(data).encode() if data is not None else None,capture_output=True,check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    manifest=json.loads((ROOT/'results/pages_frontend_deployment_manifest.json').read_text(encoding='utf-8'))
    files=manifest['files'];assert len(files)==len(set(files))
    for name in files:
        p=ROOT/name
        assert p.resolve().parent==(ROOT/'site').resolve() and p.suffix in {'.html','.js','.json'} and not p.is_symlink()
        assert p.stat().st_size<12*1024*1024
    head=api('git/ref/heads/main')['object']['sha']
    base=api(f'git/commits/{head}')['tree']['sha']
    root=api(f'git/trees/{base}')['tree']
    site=next((r['sha'] for r in root if r['path']=='site' and r['type']=='tree'),None)
    existing={'site/'+r['path']:r['sha'] for r in api(f'git/trees/{site}')['tree']} if site else {}
    entries=[]
    for name in files:
        content=(ROOT/name).read_bytes();sha=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        if existing.get(name)==sha:continue
        created=api('git/blobs','POST',{'encoding':'base64','content':base64.b64encode(content).decode()})
        assert created['sha']==sha
        entries.append({'path':name,'mode':'100644','type':'blob','sha':sha})
        print('Prepared',name,flush=True)
    if not entries:print('Frontend already matches remote main');return
    tree=api('git/trees','POST',{'base_tree':base,'tree':entries})
    commit=api('git/commits','POST',{'message':'Sync Pages with current local analyzer and add opt-in backend connection','tree':tree['sha'],'parents':[head]})
    # This fails on concurrent divergent main changes; never force-push.
    api('git/refs/heads/main','PATCH',{'sha':commit['sha'],'force':False})
    receipt={'repository':REPO,'parent':head,'commit':commit['sha'],'url':f'https://github.com/{REPO}/commit/'+commit['sha'],'files':[e['path'] for e in entries],'local_branch_or_index_modified':False}
    (ROOT/'results/pages_frontend_publication.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt,indent=2),flush=True)


if __name__=='__main__':main()
