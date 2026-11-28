"""Upload isolated source/tokenizer snapshot, launch and collect H200 audit."""
import argparse
import base64
import hashlib
import json
import io
import sys
import tarfile
import zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute,upload_file
CONFIG=ROOT/'hysage-kubeconfig.yaml'
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/item4-goldfree-qwen-20261126'
OUT=ROOT/'results/item4_goldfree_h200_20261126'


def launch():
    OUT.mkdir(exist_ok=True)
    old=json.loads((ROOT/'results/item4_qwen_reference_20261126/manifest.json').read_text(encoding='utf-8'))
    pin=json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_text(encoding='utf-8'))
    tok=ROOT/'models/precision_roles_qwen25_14b_v1'
    tnames=['tokenizer.json','tokenizer_config.json','chat_template.jinja']
    inputs=dict(cases=[{k:c[k] for k in ('id','record','asset_type_id')} for c in old['cases']],
        hashes=dict(base=pin['base_files_sha256'],
            adapter={'adapter_model.safetensors':old['model_identities']['exploitation-prerequisites']['adapter']['sha256']},
            tokenizer={n:hashlib.sha256((tok/n).read_bytes()).hexdigest() for n in tnames}),v3=[])
    for p in sorted((ROOT/'results/item4_qwen_v3_isolated_20261126').glob('*.json')):
        r=json.loads(p.read_text(encoding='utf-8'))
        if 'packet'in r:inputs['v3'].append({k:r[k] for k in ('id','kind','packet')})
    (OUT/'inputs.json').write_text(json.dumps(inputs,ensure_ascii=False,indent=2),encoding='utf-8')
    archive=OUT/'source_inputs.tar.gz'
    with tarfile.open(archive,'w:gz') as t:
        for p in (ROOT/'src').rglob('*'):
            if p.suffix in ('.py','.json'):t.add(p,arcname=p.relative_to(ROOT).as_posix())
        t.add(ROOT/'tools/item4/goldfree_h200_worker.py',arcname='tools/item4/goldfree_h200_worker.py')
        t.add(OUT/'inputs.json',arcname='inputs.json')
        for name in tnames+['special_tokens_map.json','added_tokens.json','merges.txt','vocab.json']:
            if (tok/name).exists():t.add(tok/name,arcname='tokenizer/'+name)
    upload_file(CONFIG,archive,REMOTE+'.tar.gz')
    code=f'''from pathlib import Path
import subprocess,tarfile,json,os
w=Path({REMOTE!r})
if (w/'worker.pid').exists():raise RuntimeError('Existing run: inspect rather than overwrite')
w.mkdir(exist_ok=True)
with tarfile.open({(REMOTE+'.tar.gz')!r}) as t:
 for member in t.getmembers():
  if not (w/member.name).resolve().is_relative_to(w.resolve()) or member.issym() or member.islnk():raise ValueError('Unsafe archive')
 t.extractall(w)
log=(w/'worker.log').open('w')
p=subprocess.Popen([str(w.parent/'venv/bin/python'),str(w/'tools/item4/goldfree_h200_worker.py')],cwd=w,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=dict(os.environ,TOKENIZERS_PARALLELISM='false',HF_HUB_OFFLINE='1'))
(w/'worker.pid').write_text(str(p.pid))
print(json.dumps(dict(pid=p.pid,run=str(w))))'''
    receipt=json.loads(execute(CONFIG,code,timeout=30))
    (OUT/'launch.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt))


def status():
    code=f'''from pathlib import Path
import json
w=Path({REMOTE!r});p=w/'outputs/status.json'
print(json.dumps(dict(status=json.loads(p.read_text()) if p.exists() else None,log_tail=(w/'worker.log').read_text(errors='replace')[-1500:] if (w/'worker.log').exists() else '')))'''
    print(execute(CONFIG,code,timeout=20))


def collect():
    code=f'''from pathlib import Path
import json,zlib,base64,hashlib
w=Path({REMOTE!r})/'outputs'
files={{p.name:json.loads(p.read_text()) for p in w.glob('*.json')}}
raw=json.dumps(files,ensure_ascii=False).encode()
print(json.dumps(dict(sha256=hashlib.sha256(raw).hexdigest(),data=base64.b64encode(zlib.compress(raw)).decode())))'''
    value=json.loads(execute(CONFIG,code,timeout=30))
    raw=zlib.decompress(base64.b64decode(value['data']))
    if hashlib.sha256(raw).hexdigest()!=value['sha256']:raise ValueError('Transfer hash mismatch')
    data=json.loads(raw)
    dest=OUT/'outputs';dest.mkdir(exist_ok=True)
    for name,value in data.items():
        if Path(name).name!=name:raise ValueError('Unexpected output filename')
        (dest/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'collection.json').write_text(json.dumps(dict(transfer_sha256=hashlib.sha256(raw).hexdigest(),files=len(data)),indent=2),encoding='utf-8')
    print(json.dumps(dict(files=len(data),status=data.get('status.json'))))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['launch','status','collect']);a=p.parse_args()
    {'launch':launch,'status':status,'collect':collect}[a.action]()
