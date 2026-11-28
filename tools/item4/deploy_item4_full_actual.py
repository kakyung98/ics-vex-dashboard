"""Hash-checked isolated H200 deployment of the full, current #4 evaluation."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import argparse
import hashlib
import json
import tarfile
import subprocess

from tools.common.ncp_api_transport import execute, upload_file

ROOT=Path(__file__).resolve().parents[2]
MIGRATION='/home/irteam/data-vol1/ics-vex-migration-20261116'
WORK=MIGRATION+'/item4-full-actual-20261120-v8'
LOCAL=ROOT/'results/item4_full_actual_20261120'
CONFIG=ROOT/'hysage-kubeconfig.yaml'


def package(include_data=True):
    LOCAL.mkdir(parents=True,exist_ok=True)
    files=[]
    for directory in ['src','tools','local-service','site','docs','icsa/csaf']:
        for p in (ROOT/directory).rglob('*'):
            if p.is_file() and p.suffix.lower() in {'.py','.json','.html','.js','.css','.md','.csv'} and '__pycache__' not in p.parts:
                files.append(p)
    for directory in ['data/nist_auto_vex','data/standards']:
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file())
    for rel in ['data/operator_asset_keys.csv.gz','data/identification_runtime.json','data/prerequisite_adapter_roles.json',
                'data/cisa_advisories.json','data/cisa_reference_manifest.json',
                'data/cpe_dictionary.jsonl','data/identity_aliases_v3.json',
                'models/precision_roles_qwen25_14b_v1/training_complete.json']:
        p=ROOT/rel
        if p.is_file():files.append(p)
    if include_data:
        for name in ['full_population_inputs.jsonl','full_population_gold.jsonl','full_population_index.json','full_population_manifest.json']:
            files.append(ROOT/'benchmark/item4_evaluation'/name)
    files=sorted(set(files))
    manifest={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (LOCAL/'transfer_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    archive=Path('D:/ICS-VEX-support/task-temp/item4_full_actual_transfer.tar.gz')
    with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
        for p in files:tar.add(p,arcname=p.relative_to(ROOT).as_posix(),recursive=False)
        tar.add(LOCAL/'transfer_manifest.json',arcname='transfer_manifest.json')
    print(json.dumps(dict(stage='packaged',files=len(files),bytes=archive.stat().st_size)),flush=True)
    return archive


def deploy():
    state=json.loads(execute(CONFIG,"from pathlib import Path;import json;p=Path("+repr(WORK)+");print(json.dumps({'exists':(p/'results/item4_full_actual_20261120/status.json').exists()}))",timeout=30))
    if state['exists']:raise RuntimeError('Run exists; use status/resume without replacing frozen inputs')
    archive=package()
    upload_file(CONFIG,archive,WORK+'/incoming.tar.gz',timeout=60)
    script='''from pathlib import Path
import json,tarfile,hashlib,os,shutil
w=Path(WORK);r=Path(MIGRATION)
with tarfile.open(w/'incoming.tar.gz') as tar:
 for m in tar.getmembers():
  if not (w/m.name).resolve().is_relative_to(w.resolve()):raise ValueError('Unsafe archive member')
 tar.extractall(w)
for rel,h in json.loads((w/'transfer_manifest.json').read_text()).items():
 assert hashlib.sha256((w/rel).read_bytes()).hexdigest()==h,rel
original_marker=json.loads((w/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_text())
old=r/'project/models/precision_roles_qwen25_14b_v1';dest=w/'models/precision_roles_qwen25_14b_v1'
for p in old.iterdir():
 if p.is_file() and p.name!='training_complete.json':
  if not (dest/p.name).exists():(dest/p.name).symlink_to(p)
assert hashlib.sha256((dest/'adapter_model.safetensors').read_bytes()).hexdigest()==original_marker['adapter_sha256']
original_marker['base']=str(r/'base_model')
(dest/'training_complete.json').write_text(json.dumps(original_marker,indent=2))
vep=r/'operator-vep-real-v2-20261119-r1/trained/vep_extraction'
adapter=w/'models/production_vep_extraction';adapter.mkdir(exist_ok=True)
for p in vep.iterdir():
 if not p.is_file():continue
 if p.name in {'adapter_config.json','training_complete.json'}:
  v=json.loads(p.read_text());key='base_model_name_or_path' if p.name=='adapter_config.json' else 'base';v[key]=str(r/'base_model');(adapter/p.name).write_text(json.dumps(v,indent=2))
 else:(adapter/p.name).symlink_to(p)
assert hashlib.sha256((adapter/'adapter_model.safetensors').read_bytes()).hexdigest()=='7ce8bfea47c7c226092566396cf75972a3cccc1305f0137e5953f3ba6882ebaf'
roles=json.loads((w/'data/prerequisite_adapter_roles.json').read_text());roles['storage_roots']=[str(w/'models')];roles['roles']['exploitation-prerequisites']['path']='models/production_vep_extraction';(w/'data/prerequisite_adapter_roles.json').write_text(json.dumps(roles,indent=2))
print(json.dumps(dict(deployed=str(w),files_verified=len(json.loads((w/'transfer_manifest.json').read_text())),base_and_adapter_bytes_preserved=True)))
'''.replace('WORK',repr(WORK)).replace('MIGRATION',repr(MIGRATION))
    print(execute(CONFIG,script,timeout=45))


def start(limit=None):
    args=['-B','-u','-m','tools.item4.run_item4_full_actual','--engine','hf_xgrammar_compact_cached_rolling','--batch-size','64','--threads','128']
    if limit:args+=['--limit',str(limit)]
    script='''from pathlib import Path
import subprocess,os,json
w=Path(WORK);r=Path(MIGRATION)
p=w/'worker.pid'
if p.exists():
 try:os.kill(int(p.read_text()),0)
 except ProcessLookupError:pass
 else:raise RuntimeError('Worker is already running; do not duplicate inference')
env=dict(os.environ,ICSVEX_MIGRATION_ROOT=str(r),LOCALAPPDATA=str(w/'runtime'),HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONUNBUFFERED='1')
cc=r/'item4-vllm-venv/bin/item4-cc';cxx=r/'item4-vllm-venv/bin/item4-cxx'
if cc.is_file():env['CC']=str(cc)
if cxx.is_file():env['CXX']=str(cxx)
out=w/'results/item4_full_actual_20261120';out.mkdir(parents=True,exist_ok=True)
(out/'runtime_environment.json').write_text(json.dumps({k:env.get(k) for k in ['CC','CXX','HF_HUB_OFFLINE','TRANSFORMERS_OFFLINE','LOCALAPPDATA']},indent=2))
env.pop('ICS_PREREQUISITE_LLM_URL',None);env.pop('ICS_PREREQUISITE_LLM_MODEL',None)
log=(w/'worker.log').open('a')
proc=subprocess.Popen([str(r/'venv/bin/python'),*ARGS],cwd=w,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
p.write_text(str(proc.pid));print(json.dumps(dict(pid=proc.pid,work=str(w))))
'''.replace('Path(WORK)','Path('+repr(WORK)+')').replace('Path(MIGRATION)','Path('+repr(MIGRATION)+')').replace('ARGS',repr(args))
    print(execute(CONFIG,script,timeout=30))


def status():
    script='''from pathlib import Path
import json,os
w=Path(WORK);p=w/'results/item4_full_actual_20261120/status.json'
s=json.loads(p.read_text()) if p.exists() else {'status':'not_started'}
pid=int((w/'worker.pid').read_text()) if (w/'worker.pid').exists() else None
try:os.kill(pid,0);s['process_alive']=True
except (ProcessLookupError,TypeError):s['process_alive']=False
log=w/'worker.log';s['log_tail']=log.read_text(errors='replace').splitlines()[-8:] if log.exists() else []
p=w/'results/item4_full_actual_20261120/generation_progress.json'
if p.exists():s['generation_progress']=json.loads(p.read_text())
print(json.dumps(s))
'''.replace('WORK',repr(WORK))
    raw=execute(CONFIG,script,timeout=30)
    LOCAL.mkdir(exist_ok=True,parents=True)
    (LOCAL/'remote_status.json').write_text(raw,encoding='utf-8')
    print(raw)


def fetch():
    script='''from pathlib import Path
import json,tarfile,hashlib,sys
w=Path(WORK);out=w/'results/item4_full_actual_20261120'
assert json.loads((out/'status.json').read_text())['status']=='complete','Evaluation is still running'
archive=w/'full_actual_results.tar.gz'
files=[p for p in out.rglob('*') if p.is_file() and 'mulval_runs' not in p.parts and p.name!='delivery_manifest.json']
manifest={}
for i,p in enumerate(files):
 manifest[p.relative_to(out).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
 if i%1000==0:print('Result hash heartbeat: '+str(i),file=sys.stderr,flush=True)
(out/'delivery_manifest.json').write_text(json.dumps(manifest,indent=2))
with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
 for i,p in enumerate(files):
  tar.add(p,arcname=p.relative_to(out).as_posix(),recursive=False)
  if i%1000==0:print('Result archive heartbeat: '+str(i),file=sys.stderr,flush=True)
 tar.add(out/'delivery_manifest.json',arcname='delivery_manifest.json')
 tar.add(w/'transfer_manifest.json',arcname='source_transfer_manifest.json')
print(json.dumps(dict(bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),files=len(files))))
'''.replace('WORK',repr(WORK))
    receipt=json.loads(execute(CONFIG,script,timeout=60))
    from tools.common.ncp_transport import command
    destination=Path('D:/ICS-VEX-support/task-temp/item4_full_actual_results.tar.gz')
    with destination.open('wb') as stream:
        subprocess.run(command(CONFIG)+['cat',WORK+'/full_actual_results.tar.gz'],stdout=stream,check=True)
    assert hashlib.sha256(destination.read_bytes()).hexdigest()==receipt['sha256']
    with tarfile.open(destination) as tar:
        for m in tar.getmembers():
            if not m.isfile() or not (LOCAL/m.name).resolve().is_relative_to(LOCAL.resolve()):
                raise ValueError('Unsafe result archive member')
        tar.extractall(LOCAL)
    manifest=json.loads((LOCAL/'delivery_manifest.json').read_bytes())
    for rel,h in manifest.items():assert hashlib.sha256((LOCAL/rel).read_bytes()).hexdigest()==h,rel
    (LOCAL/'delivery_receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(dict(fetched=True,**receipt)),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['deploy','start','status','fetch'])
    parser.add_argument('--limit',type=int)
    args=parser.parse_args()
    if args.action=='deploy':deploy()
    elif args.action=='start':start(args.limit)
    elif args.action=='fetch':fetch()
    else:status()
