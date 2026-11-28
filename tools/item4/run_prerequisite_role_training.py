"""Isolated H200 run orchestration for the two full-population role adapters."""
from pathlib import Path
import argparse,base64,hashlib,io,json,subprocess,sys,tarfile,time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from tools.common.ncp_api_transport import execute,upload_file

RUN='prerequisite-role-adapters-20261119-v2'
REMOTE_ROOT='/home/irteam/data-vol1/ics-vex-migration-20261116'
REMOTE=REMOTE_ROOT+'/'+RUN
OUT=ROOT/'results/role_adapters_20261119_v2'
DATA=ROOT/'benchmark/prerequisite_roles_20261119_v7'
CONFIG=ROOT/'hysage-kubeconfig.yaml'

JOB=r'''from pathlib import Path
import fcntl,json,os,subprocess,time,traceback
w=Path(__file__).resolve().parent;r=w.parent
status=w/'job_status.json'
def save(**values):
 tmp=status.with_suffix('.tmp');tmp.write_text(json.dumps(dict(updated_at=time.time(),**values),indent=2));tmp.replace(status)
lock=(w/'run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 save(state='waiting',stage='exclusive_gpu_lock')
 gpu=(r/'item4-automatic-runs/gpu.lock').open('a');fcntl.flock(gpu,fcntl.LOCK_EX)
 save(state='running',stage='exclusive_training',memory_limit_gib=112)
 args=[str(r/'venv/bin/python'),str(w/'tools/item4/train_prerequisite_role_adapters.py'),
       '--data',str(w/'dataset'),'--base',str(r/'base_model'),'--base-pin',str(w/'base_pin.json'),
       '--output',str(w/'trained'),'--memory-gib','112','--batch-size','8','--dequantize-frozen-base']
 code=subprocess.call(args,cwd=w)
 if code:raise RuntimeError('Training exited with code '+str(code))
 save(state='running',stage='heldout_evaluation')
 code=subprocess.call([str(r/'venv/bin/python'),str(w/'tools/item4/evaluate_prerequisite_role_adapters.py'),
       '--data',str(w/'dataset'),'--base',str(r/'base_model'),'--base-pin',str(w/'base_pin.json'),
       '--adapters',str(w/'trained'),'--output',str(w/'evaluation')],cwd=w)
 if code:raise RuntimeError('Evaluation exited with code '+str(code))
 save(state='complete',stage='two_adapters_trained_and_evaluated')
except Exception:save(state='failed',error=traceback.format_exc());raise
'''


def pack():
    from tools.item4.build_prerequisite_role_data import audit
    audit(DATA);OUT.mkdir(parents=True,exist_ok=True)
    path=OUT/'training_inputs.tar.gz'
    with path.open('wb',buffering=4*1024*1024) as raw_stream,tarfile.open(fileobj=raw_stream,mode='w:gz',compresslevel=1) as archive:
        archive.add(DATA,arcname='dataset')
        archive.add(ROOT/'tools/item4/train_prerequisite_role_adapters.py',arcname='tools/item4/train_prerequisite_role_adapters.py')
        archive.add(ROOT/'tools/item4/evaluate_prerequisite_role_adapters.py',arcname='tools/item4/evaluate_prerequisite_role_adapters.py')
        for source in (ROOT/'src').rglob('*.py'):archive.add(source,arcname=source.relative_to(ROOT).as_posix())
        archive.add(OUT/'base_pin.json',arcname='base_pin.json')
        raw=JOB.encode();info=tarfile.TarInfo('job.py');info.size=len(raw);archive.addfile(info,io.BytesIO(raw))
    return path


def launch():
    archive=pack();upload_file(CONFIG,archive,REMOTE+'.tar.gz')
    script=f'''from pathlib import Path
import json,subprocess,tarfile,os
w=Path({REMOTE!r})
if (w/'job.pid').exists():raise RuntimeError('Run already exists; inspect status instead of overwriting')
w.mkdir(parents=True,exist_ok=True)
with tarfile.open({(REMOTE+'.tar.gz')!r}) as a:
 for entry in a.getmembers():
  p=(w/entry.name).resolve()
  if w.resolve() not in p.parents:raise RuntimeError('Archive path escapes run')
 a.extractall(w)
log=(w/'job.log').open('w')
p=subprocess.Popen([str(w.parent/'venv/bin/python'),str(w/'job.py')],cwd=w,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=dict(os.environ,TOKENIZERS_PARALLELISM='false'))
(w/'job.pid').write_text(str(p.pid))
print(json.dumps(dict(pid=p.pid,run=str(w),population=12418,memory_limit_gib=32)))'''
    receipt=json.loads(execute(CONFIG,script,timeout=45))
    (OUT/'launch.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))


def status(compact=False,persist=True):
    script=f'''from pathlib import Path
import json
w=Path({REMOTE!r});result={{}}
for rel in ['job_status.json','trained/status.json','trained/failure.json','evaluation/status.json','evaluation/failure.json','evaluation/report.json']:
 p=w/rel
 if p.exists():result[rel]=json.loads(p.read_text())
result['log_tail']=(w/'job.log').read_text(errors='replace')[-2500:] if (w/'job.log').exists() else ''
result['worker_alive']=False
if (w/'job.pid').exists():
 result['worker_pid']=int((w/'job.pid').read_text())
 try:
  argv=(Path('/proc')/str(result['worker_pid'])/'cmdline').read_bytes().split(bytes([0]))
  result['worker_alive']=any(Path(arg.decode()).resolve().parent==w.resolve() and Path(arg.decode()).name.startswith('job') for arg in argv if arg)
 except (OSError,UnicodeError):pass
print(json.dumps(result))'''
    value=json.loads(execute(CONFIG,script,timeout=30))
    if persist:
        OUT.mkdir(parents=True,exist_ok=True)
        snapshot=OUT/('latest_status.'+str(time.time_ns())+'.tmp')
        snapshot.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
        snapshot.replace(OUT/'latest_status.json')
    if compact:
        trainer=value.get('trained/status.json',{});evaluation=value.get('evaluation/status.json',{})
        summary=dict(job=value.get('job_status.json'),worker_alive=value.get('worker_alive'),training={k:trainer.get(k) for k in ('state','stage','completed','optimizer_updates','mean_loss','batch_size','allocated_vram_gib','elapsed_seconds')},evaluation=evaluation)
        if value.get('trained/failure.json') or value.get('evaluation/failure.json') or value.get('job_status.json',{}).get('state')=='failed':summary['log_tail']=value['log_tail']
        print(json.dumps(summary,ensure_ascii=False))
    else:print(json.dumps(value,ensure_ascii=False))
    return value


def watch():
    """Observe this specific run in the active task; never launch another run."""
    while True:
        try:value=status(compact=True,persist=False)
        except Exception as exc:
            print(json.dumps(dict(observation_error=type(exc).__name__,retry_seconds=30)),flush=True)
            time.sleep(30);continue
        state=value.get('job_status.json',{}).get('state')
        sys.stdout.flush()
        if state=='complete':return
        if state=='failed':raise RuntimeError('Training/evaluation failed; inspect latest_status.json')
        if not value.get('worker_alive'):raise RuntimeError('Pipeline process is absent; inspect checkpoints and pod health before resuming')
        time.sleep(30)


def fetch():
    script=f'''from pathlib import Path
import json,tarfile
w=Path({REMOTE!r})
if json.loads((w/'trained/status.json').read_text())['state']!='complete':raise RuntimeError('Training is not complete')
with tarfile.open(w/'trained_adapters.tar.gz','w:gz') as a:
 for alias in ['vep_extraction','operating_record_review']:a.add(w/'trained'/alias,arcname=alias)
 if (w/'evaluation').exists():a.add(w/'evaluation',arcname='evaluation')
print('ready')'''
    execute(CONFIG,script,timeout=30)
    destination=OUT/'trained_adapters.tar.gz'
    wire=execute(CONFIG,'from pathlib import Path; import base64,sys; sys.stdout.write(base64.b64encode(Path('+repr(REMOTE+'/trained_adapters.tar.gz')+').read_bytes()).decode())',timeout=60)
    destination.write_bytes(base64.b64decode(wire,validate=True))
    extracted=OUT/'trained';extracted.mkdir(exist_ok=True)
    with tarfile.open(destination) as archive:
        for entry in archive.getmembers():
            p=(extracted/entry.name).resolve()
            if extracted.resolve() not in p.parents:raise ValueError('Adapter archive path escapes result directory')
        archive.extractall(extracted)
    for alias in ('vep_extraction','operating_record_review'):
        folder=extracted/alias;marker=json.loads((folder/'training_complete.json').read_text())
        if hashlib.sha256((folder/'adapter_model.safetensors').read_bytes()).hexdigest()!=marker['adapter_sha256']:
            raise ValueError('Downloaded adapter hash mismatch')
    print(json.dumps(dict(downloaded=str(extracted),roles=2)))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['launch','status','fetch','watch'])
    parser.add_argument('--compact',action='store_true')
    args=parser.parse_args();status(args.compact) if args.action=='status' else globals()[args.action]()
