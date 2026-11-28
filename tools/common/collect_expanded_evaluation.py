"""Bounded status and verified artifact retrieval; never download auth files."""
from pathlib import Path
import argparse,base64,hashlib,json,sys,tarfile
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute
from tools.common.task_dns_transport import kube_dns_fallback
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/item4-expanded-evaluation-20261127'
LOCAL=ROOT/'results/item4_expanded_evaluation_20261127'
CONFIG=ROOT/'hysage-kubeconfig.yaml'

def status():
    code='''from pathlib import Path
import json,os
r=Path(REMOTE);p=r/'item4';s=p/'status.json'
x=json.loads(s.read_text()) if s.exists() else dict(state='starting')
try:os.kill(int((p/'pid').read_text()),0);x['worker_exists']=True
except (ProcessLookupError,FileNotFoundError):x['worker_exists']=False
if x.get('state')=='failed':x['log_tail']=(p/'worker.log').read_text()[-3000:]
print(json.dumps(x,ensure_ascii=True))
'''.replace('REMOTE',repr(REMOTE))
    print(execute(CONFIG,code,timeout=30))

def collect():
    code='''from pathlib import Path
import tarfile,hashlib,json
r=Path(REMOTE);p=r/'item4';s=json.loads((p/'status.json').read_text())
if s['state']!='predictions_complete':raise RuntimeError('Inference incomplete')
freeze=json.loads((r/'freeze.json').read_text())
bad=[k for k,h in freeze['runtime_files'].items() if hashlib.sha256((r/k).read_bytes()).hexdigest()!=h]
assert not bad,bad
assert hashlib.sha256((p/'inputs.json').read_bytes()).hexdigest()==freeze['input_sha256']['item4']
(r/'integrity_remote.json').write_text(json.dumps(dict(frozen_sources_verified=True,inputs_verified=True,freeze_sha256=hashlib.sha256((r/'freeze.json').read_bytes()).hexdigest())))
out=r/'completed_artifacts.tar.gz'
with tarfile.open(out,'w:gz') as t:
 for name in ['freeze.json','integrity_remote.json','item4/status.json','item4/worker.log','item4/native_cache/inference_timing.jsonl','item4/predictions','item4/raw_calls']:
  if (r/name).exists():t.add(r/name,arcname=name)
print(json.dumps(dict(size=out.stat().st_size,sha256=hashlib.sha256(out.read_bytes()).hexdigest())))
'''.replace('REMOTE',repr(REMOTE))
    metadata=json.loads(execute(CONFIG,code,timeout=30));archive=LOCAL/'completed_artifacts.tar.gz'
    with archive.open('wb') as out:
        for offset in range(0,metadata['size'],524288):
            code=f"from pathlib import Path\nimport base64\np=Path({(REMOTE+'/completed_artifacts.tar.gz')!r})\nwith p.open('rb') as f:f.seek({offset});print(base64.b64encode(f.read(524288)).decode())"
            out.write(base64.b64decode(execute(CONFIG,code,timeout=30).strip()))
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==metadata['sha256']
    dest=(LOCAL/'collected').resolve()
    with tarfile.open(archive) as t:
        for m in t.getmembers():assert (dest/m.name).resolve().is_relative_to(dest) and not m.issym() and not m.islnk()
        t.extractall(dest)
    assert (dest/'freeze.json').read_bytes()==(LOCAL/'freeze.json').read_bytes()
    (LOCAL/'retrieval_receipt.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    print(json.dumps(dict(archive_sha256=metadata['sha256'],bytes=metadata['size'],verified=True)))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['status','collect']);a=p.parse_args()
    with kube_dns_fallback(CONFIG):globals()[a.action]()
