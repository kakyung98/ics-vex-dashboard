"""Transfer the frozen Item 3 validation plan to an isolated, hash-checked H200 run."""
from pathlib import Path
import argparse,hashlib,json,sqlite3,sys,tarfile,time,subprocess

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.item4.run_item4_source_context_h200 import execute
from tools.common.ncp_transport import upload

REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116'
RUN='20261119_parser_cisa_v1'
WORK=REMOTE+'/item3-benchmark-runs/'+RUN
LOCAL=ROOT/'results/item3_benchmark_validation_h200_20261119'
RESULT='results/item3_benchmark_validation_20261119'
TESTS=['test_identification_parsers.py','test_identification_without_cpe.py',
       'test_identification_role_names.py','test_source_version_parser.py']


from tools.common.paths import test_path

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()


WORKER=r'''from pathlib import Path
import os,sys,time,json,traceback,subprocess,fcntl
work=Path(__file__).resolve().parent;sys.path.insert(0,str(work));os.chdir(work)
os.environ['LOCALAPPDATA']=str(work/'runtime')
os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1'
state={'stage':'starting','pid':os.getpid(),'started_at':time.time(),'status':'running'}
def save():
 p=work/'h200_status.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(state,indent=2));t.replace(p)
save()
try:
 lock=(work/'worker.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 import torch
 assert 'H200' in torch.cuda.get_device_name(0),'H200 required'
 free,total=torch.cuda.mem_get_info()
 if free<24*1024**3:raise RuntimeError('Insufficient free H200 memory; other jobs were not interrupted')
 state['gpu']=torch.cuda.get_device_name(0);state['free_memory_before_loading']=free
 state['stage']='regression_tests';save()
 tests=__TESTS__
 with (work/'tests.log').open('w') as log:
  p=subprocess.run([sys.executable,'-m','pytest',*[str(work/'tests'/t) for t in tests],'-q','--junitxml=h200_tests.xml'],cwd=work,stdout=log,stderr=subprocess.STDOUT)
 if p.returncode:raise RuntimeError('H200 regression tests failed; see tests.log')
 from tools.item3.run_item3_benchmark_validation import run
 state['stage']='full_benchmark_validation';save()
 run(work/__RESULT__,batch_size=32,window=512)
 state.update(stage='complete',status='complete',finished_at=time.time());save()
except BaseException:
 state.update(status='failed',error=traceback.format_exc(),finished_at=time.time());save();raise
'''.replace('__TESTS__',repr(TESTS)).replace('__RESULT__',repr(RESULT))


def package():
    from tools.item3.run_item3_benchmark_validation import signature
    LOCAL.mkdir(parents=True,exist_ok=True)
    source=ROOT/RESULT/'validation.sqlite3';backup=LOCAL/'validation.sqlite3'
    src=sqlite3.connect(source,timeout=60);dst=sqlite3.connect(backup)
    src.backup(dst);src.close()
    assert dst.execute("select value from meta where name='signature'").fetchone()[0]==signature()[1]
    # Repeat all model inference on H200; retain CPU rules under the same frozen signature.
    dst.execute('update units set agents=null');dst.execute('delete from case_results');dst.commit();dst.close()
    worker=LOCAL/'h200_worker.py';worker.write_text(WORKER,encoding='utf-8')
    files=[(backup,RESULT+'/validation.sqlite3'),(worker,'h200_worker.py')]
    files += [(p,p.relative_to(ROOT).as_posix()) for folder in ('src','tools') for p in (ROOT/folder).rglob('*.py')]
    files += [(p,p.relative_to(ROOT).as_posix()) for p in (ROOT/'benchmark/item3_evaluation/evaluation').glob('*.py')]
    files += [(ROOT/rel,rel) for rel in ('benchmark/__init__.py','benchmark/item3_evaluation/__init__.py',
              'benchmark/item3_evaluation/evaluate.py','src/layout.json','tools/layout.json')]
    files += [(test_path(t, root=ROOT),test_path(t,root=ROOT).relative_to(ROOT).as_posix()) for t in TESTS]
    for rel in ['data/cpe_dictionary.jsonl','data/identity_aliases_v3.json',
                'data/item3_identification_sources_v11/cves.jsonl','data/item3_identification_sources_v11/manifest.json',
                'data/cisa_advisories.json','data/cisa_reference_manifest.json']:
        files.append((ROOT/rel,rel))
    files += [(p,p.relative_to(ROOT).as_posix()) for p in (ROOT/'data/cisa_identification_csaf').glob('*.json')]
    for name in ('inventory.json','web_regression.json','README.txt','input_integrity_initial.json'):
        p=ROOT/RESULT/name
        if p.is_file():files.append((p,RESULT+'/'+name))
    manifest={rel:sha(p) for p,rel in files}
    m=LOCAL/'transfer_manifest.json';m.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    archive=LOCAL/'h200_inputs.tar.gz'
    with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
        for p,rel in files:tar.add(p,arcname=rel,recursive=False)
        tar.add(m,arcname='transfer_manifest.json',recursive=False)
    print(json.dumps({'archive':str(archive),'bytes':archive.stat().st_size,'files':len(files),'sha256':sha(archive)}),flush=True)
    return archive


def start(config):
    existing=json.loads(execute(config,"from pathlib import Path;import json;w=Path("+repr(WORK)+");print(json.dumps({'started':(w/'h200_status.json').exists()}))"))
    if existing['started']:raise RuntimeError('This run already started; use status/fetch instead of replacing its checkpoint')
    archive=package();destination=WORK+'/incoming.tar.gz'
    upload(config,archive,destination)
    script='''from pathlib import Path
import tarfile,hashlib,json,os,subprocess
work=Path(WORK);root=Path(REMOTE)
with tarfile.open(work/'incoming.tar.gz') as tar:
 for member in tar.getmembers():
  if not (work/member.name).resolve().is_relative_to(work.resolve()):raise ValueError('Unsafe archive member')
 tar.extractall(work)
manifest=json.loads((work/'transfer_manifest.json').read_text())
for rel,expected in manifest.items():
 h=hashlib.sha256()
 with (work/rel).open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 assert h.hexdigest()==expected,rel
source=root/'project/models/precision_roles_qwen25_14b_v1'
target=work/'models/precision_roles_qwen25_14b_v1';target.parent.mkdir(parents=True,exist_ok=True)
if not target.exists():target.symlink_to(source,target_is_directory=True)
marker=json.loads((source/'training_complete.json').read_text())
assert hashlib.sha256((source/'adapter_model.safetensors').read_bytes()).hexdigest()==marker['adapter_sha256']
relocation={'adapter_source':str(source),'remote_marker':marker,'shared_base_weights_unchanged':True,'model_inference_restarted_on_h200':True,'batch_size':32,'window':512,'other_gpu_jobs_interrupted':False}
(work/'relocation.json').write_text(json.dumps(relocation,indent=2))
env=dict(os.environ,PYTHONHASHSEED='0',LOCALAPPDATA=str(work/'runtime'),HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
with (work/'worker.log').open('ab') as log:
 p=subprocess.Popen([str(root/'venv/bin/python'),'-B','-u',str(work/'h200_worker.py')],cwd=work,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
(work/'worker.pid').write_text(str(p.pid))
print(json.dumps({'pid':p.pid,'work':str(work),'verified_files':len(manifest)}))
'''.replace('WORK',repr(WORK)).replace('REMOTE',repr(REMOTE))
    print(execute(config,script),flush=True)


def status(config):
    script='''from pathlib import Path
import json,sqlite3
w=Path(WORK);s=json.loads((w/'h200_status.json').read_text()) if (w/'h200_status.json').is_file() else {}
pid=s.get('pid');process=Path('/proc')/str(pid)/'cmdline'
s['worker_alive']=bool(process.is_file() and any(name in process.read_bytes() for name in (b'h200_worker.py',b'aggregation_driver.py')))
if s.get('status')=='running' and not s['worker_alive']:s['status']='worker_not_running'
supervisor=w/'supervisor_status.json'
if supervisor.is_file():
 observed=json.loads(supervisor.read_text());p=Path('/proc')/str(observed.get('pid'))/'cmdline'
 observed['alive']=bool(p.is_file() and b'h200_supervisor.py' in p.read_bytes());s['supervisor']=observed
 if s['status']=='worker_not_running' and observed['alive'] and observed.get('status')=='running':
  s['status']='running';s['stage']=observed['stage']
guard=w/'memory_guard_status.json'
if guard.is_file():s['memory_guard']=json.loads(guard.read_text())
p=w/RESULT/'validation.sqlite3'
if p.is_file():
 db=sqlite3.connect('file:'+str(p)+'?mode=ro',uri=True);n,a,r=db.execute('select count(*),count(agents),count(rules) from units').fetchone()
 s['counts']={'units':n,'agents_done':a,'rules_done':r};db.close()
p=w/RESULT/'progress.json'
if p.is_file():s['progress']=json.loads(p.read_text())
print(json.dumps(s))
'''.replace('WORK',repr(WORK)).replace('RESULT',repr(RESULT))
    for attempt in range(3):
        try:value=json.loads(execute(config,script));break
        except Exception:
            if attempt==2:raise
            time.sleep(1)
    LOCAL.mkdir(parents=True,exist_ok=True)
    (LOCAL/'remote_status.json').write_text(json.dumps(value,indent=2),encoding='utf-8')
    print(json.dumps(value,ensure_ascii=False),flush=True)
    return value


def fetch(config):
    if status(config).get('status')!='complete':raise RuntimeError('H200 validation is not complete')
    # Seal off the exec connection: compression may take longer than one API request.
    sealer='''from pathlib import Path
import tarfile,json,hashlib,sqlite3
w=Path(WORK);out=w/RESULT;delivery=w/'delivery';delivery.mkdir(exist_ok=True)
manifest={}
names=['report.json','case_results.jsonl','run_signature.json','execution_environment.json','progress.json','inventory.json','web_regression.json','README.txt','input_integrity_initial.json','rules_cache_provenance.json','interim_error_audit.json']
for name in ['validation.sqlite3','packet_cache.sqlite3']:
 src=sqlite3.connect(out/name);dst=sqlite3.connect(delivery/name);src.backup(dst);dst.close();src.close()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
archive=w/'delivery.tar.gz'
with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
 files=[(out/name,name) for name in names if (out/name).is_file()]
 files += [(p,'source_snapshot/'+p.relative_to(out/'source_snapshot').as_posix()) for p in (out/'source_snapshot').rglob('*') if p.is_file()]
 files += [(delivery/name,name) for name in ['validation.sqlite3','packet_cache.sqlite3']]
 files += [(w/name,name) for name in ['h200_status.json','h200_worker.py','h200_tests.xml','tests.log','relocation.json','transfer_manifest.json']]
 files += [(w/name,name) for name in ['restart_history.jsonl','supervisor_status.json','supervisor_events.jsonl','h200_supervisor.py','memory_guard_status.json','memory_watchdog.py'] if (w/name).is_file()]
 files += [(w/name,name) for name in ['aggregation_driver.py','aggregation_policy.json','aggregation.log','tools/summarize_item3_benchmark_bounded.py'] if (w/name).is_file()]
 files += [(p,'environment_segments/'+p.relative_to(w/'environment_segments').as_posix()) for p in (w/'environment_segments').rglob('*') if p.is_file()]
 for path,rel in files:manifest[rel]=sha(path);tar.add(path,arcname=rel,recursive=False)
 m=delivery/'artifacts_manifest.json';m.write_text(json.dumps(manifest,indent=2));tar.add(m,arcname=m.name)
receipt={'sha256':sha(archive),'bytes':archive.stat().st_size,'files':len(manifest)}
p=w/'delivery_meta.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(receipt));t.replace(p)
'''.replace('WORK',repr(WORK)).replace('RESULT',repr(RESULT))
    script='''from pathlib import Path
import subprocess,json
w=Path(WORK);p=w/'delivery_meta.json'
if p.exists():print(p.read_text())
elif (w/'sealer.pid').exists():print(json.dumps({'sealing':True,'pid':int((w/'sealer.pid').read_text())}))
else:
 s=w/'seal_delivery.py';s.write_text(SCRIPT)
 with (w/'sealer.log').open('wb') as log:
  child=subprocess.Popen([PYTHON,str(s)],cwd=w,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 (w/'sealer.pid').write_text(str(child.pid));print(json.dumps({'sealing':True,'pid':child.pid}))
'''.replace('WORK',repr(WORK)).replace('SCRIPT',repr(sealer)).replace('PYTHON',repr(REMOTE+'/venv/bin/python'))
    meta=json.loads(execute(config,script))
    if meta.get('sealing'):print(json.dumps(meta),flush=True);return
    from tools.common.ncp_transport import command
    archive=LOCAL/'delivery.tar.gz';temporary=archive.with_suffix('.download')
    with temporary.open('wb') as stream:
        subprocess.run(command(config)+['cat',WORK+'/delivery.tar.gz'],stdout=stream,check=True)
    if sha(temporary)!=meta['sha256']:raise ValueError('H200 delivery hash mismatch')
    temporary.replace(archive)
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if not member.isfile() or not (LOCAL/member.name).resolve().is_relative_to(LOCAL.resolve()):raise ValueError('Invalid delivery member')
        tar.extractall(LOCAL)
    manifest=json.loads((LOCAL/'artifacts_manifest.json').read_text())
    assert all(sha(LOCAL/name)==expected for name,expected in manifest.items())
    (LOCAL/'delivery_verification.json').write_text(json.dumps({**meta,'remote_work':WORK,'all_artifact_hashes_verified':True},indent=2),encoding='utf-8')
    print(json.dumps({'downloaded':True,'output':str(LOCAL),**meta}),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['start','status','fetch'])
    p.add_argument('--config',type=Path,default=ROOT/'hysage-kubeconfig.yaml');a=p.parse_args()
    {'start':start,'status':status,'fetch':fetch}[a.action](a.config)
