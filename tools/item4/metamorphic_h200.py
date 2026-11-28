"""Launch/status/collect for this benchmark's isolated Qwen H200 service."""
from pathlib import Path
import sys,json,tarfile,hashlib,base64,zlib,argparse
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute,upload_file
OUT=ROOT/'results/item4_metamorphic_synthetic_20261127'
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/item4-metamorphic-synthetic-20261127'
CONFIG=ROOT/'hysage-kubeconfig.yaml'


def launch():
    archive=OUT/'source_inputs.tar.gz'
    with tarfile.open(archive,'w:gz') as tar:
        for p in (ROOT/'src').rglob('*'):
            if p.suffix in ('.py','.json'):tar.add(p,arcname=p.relative_to(ROOT).as_posix())
        tar.add(ROOT/'tools/item4/run_metamorphic_synthetic.py',arcname='tools/item4/run_metamorphic_synthetic.py')
        tar.add(ROOT/'tools/item4/train_synthetic_vep_adapter.py',arcname='tools/item4/train_synthetic_vep_adapter.py')
        for name in ('inputs.json','gold.json','dataset_manifest.json'):tar.add(OUT/name,arcname='evaluation/'+name)
        tar.add(ROOT/'data/prerequisite_adapter_roles.json',arcname='data/prerequisite_adapter_roles.json')
        tar.add(ROOT/'data/identification_runtime.json',arcname='data/identification_runtime.json')
    upload_file(CONFIG,archive,REMOTE+'.tar.gz')
    code=f'''from pathlib import Path
import subprocess,json,tarfile,os,secrets,hashlib,shutil
w=Path({REMOTE!r});r=w.parent
if (w/'worker.pid').exists():raise ValueError('Run already launched; inspect status')
w.mkdir(exist_ok=True)
with tarfile.open({(REMOTE+'.tar.gz')!r}) as t:
 for m in t.getmembers():
  if not (w/m.name).resolve().is_relative_to(w.resolve()) or m.issym() or m.islnk():raise ValueError('Unsafe member')
 t.extractall(w)
old=r/'item4-goldfree-expanded-20261126'
pin=json.loads((old/'outputs/manifest.json').read_text())['identity']
paths={{'base':r/'base_model','adapter':r/'operator-vep-real-v2-20261119-r1/trained/vep_extraction','tokenizer':old/'tokenizer'}}
actual={{}}
for group,path in paths.items():
 actual[group]={{}}
 for name,expected in pin['hashes'][group].items():
  h=hashlib.sha256()
  with (path/name).open('rb') as f:
   for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
  if h.hexdigest()!=expected:raise ValueError('Pinned weights changed: '+group+'/'+name)
  actual[group][name]=h.hexdigest()
identity=dict(model=pin['model'],hashes=actual,adapter_sha256=pin['adapter_sha256'],provider='vllm_0.12.0_bitsandbytes',
 backend_parity='Same pinned production weights; independent vLLM decoding backend',temperature=0,max_tokens=3072)
shutil.copytree(old/'tokenizer',w/'tokenizer',dirs_exist_ok=True)
tp=w/'tokenizer/tokenizer_config.json';tc=json.loads(tp.read_text())
if isinstance(tc.get('extra_special_tokens'),list):
 tc['additional_special_tokens']=list(dict.fromkeys(tc.get('additional_special_tokens',[])+tc['extra_special_tokens']))
 tc['extra_special_tokens']={{}};tp.write_text(json.dumps(tc))
 identity['tokenizer_compatibility_patch']='Legacy extra_special_tokens list relocated to additional_special_tokens; tokenizer.json vocabulary and token IDs unchanged.'
 identity['runtime_tokenizer_config_sha256']=hashlib.sha256(tp.read_bytes()).hexdigest()
(w/'identity.json').write_text(json.dumps(identity,indent=2))
token=secrets.token_urlsafe(32);(w/'server.auth').write_text(token);(w/'server.auth').chmod(0o600)
args=json.loads((old/'server_command.json').read_text())
args[args.index('--port')+1]='18972'
args[args.index('--tokenizer')+1]=str(w/'tokenizer')
args[args.index('--gpu-memory-utilization')+1]='0.12'
args[args.index('--max-num-seqs')+1]='8'
args+=['--enable-prefix-caching']
args+=['--api-key',token]
env=dict(os.environ,TOKENIZERS_PARALLELISM='false',HF_HUB_OFFLINE='1',VLLM_ALLOW_RUNTIME_LORA_UPDATING='False')
server=subprocess.Popen(args,cwd=w,stdout=(w/'server.log').open('w'),stderr=subprocess.STDOUT,env=env,start_new_session=True)
(w/'server.pid').write_text(str(server.pid))
worker_script="""import subprocess,time,urllib.request,json,os,signal,traceback
from pathlib import Path
w=Path(__file__).resolve().parent
try:
 ready=False
 for _ in range(180):
  try:
   q=urllib.request.Request('http://127.0.0.1:18972/v1/models',headers={{'Authorization':'Bearer '+(w/'server.auth').read_text()}})
   models=json.load(urllib.request.urlopen(q,timeout=5))
   if {{'qwen-base','vep-extraction'}}<={{x['id'] for x in models['data']}}:ready=True;break
  except Exception:time.sleep(2)
 if not ready:raise RuntimeError('Isolated Qwen service failed to start; inspect server.log')
 args=[str(w.parent/'venv/bin/python'),str(w/'tools/item4/run_metamorphic_synthetic.py'),'run','--output',str(w/'evaluation'),'--url','http://127.0.0.1:18972','--token-file',str(w/'server.auth'),'--identity-file',str(w/'identity.json'),'--workers','8']
 code=subprocess.call(args,cwd=w)
 if code:raise RuntimeError('Evaluation worker failed: '+str(code))
except Exception:
 (w/'evaluation/status.json').write_text(json.dumps(dict(state='failed',error=traceback.format_exc()),indent=2));raise
finally:
 pid=int((w/'server.pid').read_text());cmd=Path('/proc/'+str(pid)+'/cmdline')
 if cmd.exists() and b'18972' in cmd.read_bytes():os.killpg(pid,signal.SIGTERM)
"""
(w/'worker.py').write_text(worker_script)
(w/'evaluation/status.json').write_text(json.dumps(dict(state='loading',stage='isolated_qwen_service')))
worker=subprocess.Popen([str(r/'venv/bin/python'),str(w/'worker.py')],cwd=w,stdout=(w/'worker.log').open('w'),stderr=subprocess.STDOUT,start_new_session=True)
(w/'worker.pid').write_text(str(worker.pid))
print(json.dumps(dict(worker_pid=worker.pid,server_pid=server.pid,remote=str(w),port=18972,existing_service_retained=True)))
'''
    receipt=json.loads(execute(CONFIG,code,timeout=60));(OUT/'launch.json').write_text(json.dumps(receipt,indent=2));print(json.dumps(receipt))


def status():
    code=f'''from pathlib import Path
import json
w=Path({REMOTE!r});o=w/'evaluation';result={{}}
result['arm_counts']={{p.name:len(list(p.glob('*.json'))) for p in (o/'predictions/baseline').glob('*') if p.is_dir()}}
for p in w.glob('sft_trained_*/status.json'):result['training:'+p.parent.name]=json.loads(p.read_text())
if (w/'sft_supervisor_status.json').exists():result['sft_supervisor']=json.loads((w/'sft_supervisor_status.json').read_text())
for p in w.glob('sft_training_*.log'):result['log:'+p.name]=p.read_text(errors='replace')[-2000:]
for n in ('status.json','selection.json','sft_selection.json','development_baseline.json','development_faithful_atoms.json','development_logical_reading.json','development_adapter_review.json'):
 p=o/n
 if p.exists():
  value=json.loads(p.read_text())
  if 'scores' in value:value={{k:{{z:s.get(z) for z in ('cases','f1','logic_accuracy','case_accuracy','grounded_mr_rate','valid_rate')}} for k,s in value['scores'].items()}}
  if n=='status.json' and 'dev_metrics' in value:value['dev_metrics']={{k:value['dev_metrics'].get(k) for k in ('cases','f1','logic_accuracy','case_accuracy','grounded_mr_rate','valid_rate')}}
  if n=='sft_selection.json':value={{'selected':value['selected'],'above_90':value['above_90'],'validation_cases':value['validation_cases'],'metrics':{{k:{{z:s.get(z) for z in ('cases','f1','logic_accuracy','case_accuracy','grounded_mr_rate','valid_rate')}} for k,s in value['metrics'].items()}}}}
  result[n]=value
result['server_tail']=(w/'server.log').read_text(errors='replace')[-1600:] if (w/'server.log').exists() else ''
result['worker_tail']=(w/'worker.log').read_text(errors='replace')[-1000:] if (w/'worker.log').exists() else ''
token=(w/'server.auth').read_text().strip() if (w/'server.auth').exists() else ''
if token:
 result['server_tail']=result['server_tail'].replace(token,'[REDACTED]')
 result['worker_tail']=result['worker_tail'].replace(token,'[REDACTED]')
print(json.dumps(result))
'''
    result=json.loads(execute(CONFIG,code,timeout=30));(OUT/'latest_status.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))


def collect():
    # Fetch compact reports; per-call traces remain in a hash-pinned remote archive.
    code=f'''from pathlib import Path
import json,hashlib,tarfile
w=Path({REMOTE!r});o=w/'evaluation';data={{}}
for p in o.glob('*.json'):
 if p.name not in ('inputs.json','gold.json'):data[p.name]=json.loads(p.read_text())
archive=w/'evaluation_outputs.tar.gz'
with tarfile.open(archive,'w:gz') as t:
 for p in o.rglob('*.json'):t.add(p,arcname=p.relative_to(o).as_posix())
 for p in (w/'src').rglob('*'):
  if p.suffix in ('.py','.json'):t.add(p,arcname='source_snapshot/'+p.relative_to(w).as_posix())
 t.add(w/'tools/item4/run_metamorphic_synthetic.py',arcname='source_snapshot/tools/item4/run_metamorphic_synthetic.py')
 if (w/'tools/item4/train_synthetic_vep_adapter.py').exists():t.add(w/'tools/item4/train_synthetic_vep_adapter.py',arcname='source_snapshot/tools/item4/train_synthetic_vep_adapter.py')
 for name in ('evaluate_synthetic_vep_sft.py','synthetic_sft_supervisor.py'):
  if (w/'tools/item4'/name).exists():t.add(w/'tools/item4'/name,arcname='source_snapshot/tools/item4/'+name)
 for folder in w.glob('sft_data*'):
  if folder.is_dir():t.add(folder,arcname=folder.name)
 for p in w.glob('sft_identity_*.json'):t.add(p,arcname=p.name)
 for folder in w.glob('sft_trained_*'):
  if folder.is_dir():t.add(folder,arcname=folder.name)
 t.add(w/'identity.json',arcname='inference_identity.json')
data['remote_archive.json']=dict(path=str(archive),sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),bytes=archive.stat().st_size)
print(json.dumps(data))
'''
    data=json.loads(execute(CONFIG,code,timeout=60))
    for name,value in data.items():(OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
    meta=data['remote_archive.json'];destination=OUT/'evaluation_outputs.tar.gz'
    with destination.open('wb') as stream:
        for offset in range(0,meta['bytes'],512*1024):
            script="import base64\nwith open("+repr(meta['path'])+",'rb') as f:\n f.seek("+str(offset)+");print(base64.b64encode(f.read(524288)).decode())"
            stream.write(base64.b64decode(execute(CONFIG,script,timeout=30).strip(),validate=True))
    if hashlib.sha256(destination.read_bytes()).hexdigest()!=meta['sha256']:raise ValueError('Archive hash mismatch')
    expanded=(OUT/'artifacts').resolve();expanded.mkdir(exist_ok=True)
    with tarfile.open(destination) as t:
        for m in t.getmembers():
            if not (expanded/m.name).resolve().is_relative_to(expanded) or m.issym() or m.islnk():raise ValueError('Unsafe archive member')
        t.extractall(expanded)
    print(json.dumps(dict(collected=list(data),status=data.get('status.json'))))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('action',choices=['launch','status','collect']);a=p.parse_args();globals()[a.action]()
