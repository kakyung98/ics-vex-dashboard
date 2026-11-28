"""Run a frozen-model, full-population evaluation in an isolated H200 directory."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.common.ncp_transport import upload as streaming_upload

REMOTE = '/home/irteam/data-vol1/ics-vex-migration-20261116'
FILES = ['src/research/__init__.py', 
    'src/item4/evaluation/source_context_simulation.py', 'src/research/item4_source_recovery.py',
    'src/item4/decision/scoped_vex_review.py', 'src/item4/analysis/source_condition_logic.py', 'src/item4/decision/condition_logic_evaluation.py',
    'src/item4/decision/evidence_review_gate.py', 'src/common/runtime/shared_adapter_runtime.py',
    'src/common/runtime/gpu_lease.py', 'src/common/runtime/training_progress_io.py',
    'src/item4/evaluation/ground_truth_evidence.py','src/item4/analysis/advisory_source_bundles.py',
    'tools/item4/build_item4_source_context_gold.py', 'tools/item4/audit_item4_source_context.py',
    'tools/item4/evaluate_item4_source_context.py', 'tools/item4/verify_item4_source_context.py',
    'tools/item3/item3_precision_pipeline.py','tools/item4/collect_item4_grounding_sources.py',
    'tests/item4/test_item4_source_recovery.py','tests/item4/test_item4_gold_grounding.py',
    'data/item4_grounding_v1/siemens_ssa_763427.json',
]
RESULT = 'results/item4_source_context_v3_grounded_full_population'
GOLD = 'benchmark/item4_source_context_gold_v5'


def execute(config,script):
    from tools.common.ncp_api_transport import execute as bounded_execute
    packed=base64.b64encode(zlib.compress(script.encode())).decode()
    wrapper='import base64,zlib;exec(zlib.decompress(base64.b64decode('+repr(packed)+')))'
    return bounded_execute(config,wrapper,timeout=45)


def upload(config,path,destination):
    path=Path(path)
    if path.stat().st_size>512*1024:
        return streaming_upload(config,path,destination)
    raw=path.read_bytes();expected=hashlib.sha256(raw).hexdigest()
    def retry(script):
        for attempt in range(3):
            try:return execute(config,script)
            except Exception:
                if attempt==2:raise
                print(json.dumps(dict(stage='connection_retry',attempt=attempt+1)),flush=True)
    state=json.loads(retry('from pathlib import Path;import json,hashlib\np=Path('+repr(destination)+')\nb=p.read_bytes() if p.exists() else b""\nprint(json.dumps({"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}))'))
    offset=state['bytes']
    if offset>len(raw) or hashlib.sha256(raw[:offset]).hexdigest()!=state['sha256']:
        raise ValueError('Remote input prefix differs; use a new run ID')
    for offset in range(offset,len(raw),2048):
        chunk=raw[offset:offset+2048]
        script='''from pathlib import Path
import base64,hashlib
p=Path(__DEST__);p.parent.mkdir(parents=True,exist_ok=True)
data=base64.b64decode(__DATA__);assert hashlib.sha256(data).hexdigest()==__SHA__
if p.exists() and p.stat().st_size>__OFFSET__:
 with p.open('rb') as stream:
  stream.seek(__OFFSET__);assert stream.read(len(data))==data
else:
 with p.open('ab') as stream:
  assert stream.tell()==__OFFSET__
  stream.write(data)
'''.replace('__DEST__',repr(destination)).replace('__DATA__',repr(base64.b64encode(chunk).decode())).replace('__SHA__',repr(hashlib.sha256(chunk).hexdigest())).replace('__OFFSET__',str(offset))
        retry(script)
        if offset%16384==0:print(json.dumps(dict(stage='upload',sent=min(offset+len(chunk),len(raw)),total=len(raw))),flush=True)
    actual=retry('from pathlib import Path;import hashlib\nprint(hashlib.sha256(Path('+repr(destination)+').read_bytes()).hexdigest())').strip()
    if actual!=expected:raise ValueError('Input archive hash mismatch')
    print(json.dumps(dict(verified_input_sha256=actual)),flush=True)

WORKER = r'''
from pathlib import Path
import fcntl,hashlib,json,os,subprocess,sys,time,traceback
work=Path(__file__).resolve().parent
root=work.parent.parent
sys.path.insert(0,str(work))
state={'status':'running','stage':'admission','started_at':time.time(),'retrained':False}
def save():
 p=work/'status.json';tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(state,indent=2));tmp.replace(p)
save()
try:
 lock=(root/'item4-automatic-runs/gpu.lock').open('a')
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
from src.common import gpu_lease
 gpu_lease.FILE=root/'project/results/operational_role_finetune_v2/gpu_lease.json'
 gpu_lease.assert_inference_available()
 import torch
 if not torch.cuda.is_available() or 'H200' not in torch.cuda.get_device_name(0):raise RuntimeError('H200 required')
 state['environment']={'device':torch.cuda.get_device_name(0),'torch':torch.__version__,'python':sys.version}
 state['stage']='tests';save()
 with (work/'tests.log').open('w') as log:
  test=subprocess.run([sys.executable,'-m','pytest','tests/item4/test_item4_source_recovery.py','tests/item4/test_item4_gold_grounding.py','-q','--junitxml=tests.xml'],cwd=work,stdout=log,stderr=subprocess.STDOUT)
 if test.returncode:raise RuntimeError('Source recovery tests failed')
 from tools.item4.build_item4_source_context_gold import DATA,build
 if not (DATA/'manifest.json').exists():
  state['stage']='building_product_grounded_gold';save();build()
 state['stage']='gold_audit';save()
 from tools.item4.audit_item4_source_context import audit
 audit()
 from tools import evaluate_item4_source_context as evaluator
 state['gold_manifest_sha256']=hashlib.sha256((evaluator.DATA/'manifest.json').read_bytes()).hexdigest()
 state['population']=12418;state['stage']='model_evaluation';save()
 evaluator.evaluate(batch_size=32,token_budget=32768)
 state['stage']='independent_rescore';save()
 from tools.item4.verify_item4_source_context import verify
 verify()
 state.update(status='complete',stage='complete',finished_at=time.time());save()
except BaseException:
 state.update(status='failed',error=traceback.format_exc(),finished_at=time.time());save();raise
'''


def remote_status(config, work):
    from tools.common.ncp_api_transport import execute as bounded_execute
    script = """from pathlib import Path
import json
w=Path(WORK)
state=json.loads((w/'status.json').read_text()) if (w/'status.json').exists() else {'status':'not_started'}
p=w/RESULT/'status.json'
if p.exists():state['progress']=json.loads(p.read_text())
p=w/'worker.log'
if p.exists():state['last_log_lines']=p.read_text(errors='replace').splitlines()[-4:]
print(json.dumps(state))
""".replace('WORK', repr(work)).replace('RESULT', repr(RESULT))
    return json.loads(bounded_execute(config, script, timeout=30))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, default=ROOT/'hysage-kubeconfig.yaml')
    p.add_argument('--run-id', required=True)
    p.add_argument('--data', type=Path, default=ROOT/GOLD)
    p.add_argument('--build-gold', action='store_true',help='Build corrected Gold from sealed remote originals before auditing and inference')
    p.add_argument('--output', type=Path, default=ROOT/RESULT)
    p.add_argument('action', choices=['start', 'status', 'fetch'])
    a = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+', a.run_id):p.error('Invalid run ID')
    work = REMOTE+'/item4-source-context-runs/'+a.run_id
    if a.action == 'status':
        print(json.dumps(remote_status(a.config, work), ensure_ascii=False));return
    if a.action == 'fetch':
        from tools.common.ncp_api_transport import execute as bounded_execute
        script = """from pathlib import Path
import tarfile,hashlib,json
w=Path(WORK);assert json.loads((w/'status.json').read_text())['status']=='complete'
p=w/'delivery.tar.gz'
with tarfile.open(p,'w:gz') as archive:
 for name in ['status.json','job.json','worker.py','tests.log','tests.xml','code_manifest.json',RESULT,GOLD]:
  archive.add(w/name,arcname=name)
print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size,
 'gold_manifest_sha256':hashlib.sha256((w/GOLD/'manifest.json').read_bytes()).hexdigest(),
 'report_sha256':hashlib.sha256((w/RESULT/'precision_report.json').read_bytes()).hexdigest()}))
""".replace('WORK', repr(work)).replace('RESULT', repr(RESULT)).replace('GOLD',repr(GOLD))
        meta = json.loads(bounded_execute(a.config, script, timeout=45))
        if (a.data/'manifest.json').exists() and hashlib.sha256((a.data/'manifest.json').read_bytes()).hexdigest()!=meta['gold_manifest_sha256']:
            raise FileExistsError('Local Gold differs from this sealed run; choose a new --data directory')
        if (a.output/'precision_report.json').exists() and hashlib.sha256((a.output/'precision_report.json').read_bytes()).hexdigest()!=meta['report_sha256']:
            raise FileExistsError('Local result differs from this sealed run; choose a new --output directory')
        archive_path = Path(tempfile.gettempdir())/(a.run_id+'-delivery.tar.gz')
        encoded=bounded_execute(a.config,'import base64;from pathlib import Path\nprint(base64.b64encode(Path('
            +repr(work+'/delivery.tar.gz')+').read_bytes()).decode())',timeout=45)
        archive_path.write_bytes(base64.b64decode(encoded.strip(),validate=True))
        if hashlib.sha256(archive_path.read_bytes()).hexdigest()!=meta['sha256']:raise ValueError('Delivery hash mismatch')
        a.output.mkdir(parents=True,exist_ok=True)
        with tarfile.open(archive_path,'r:gz') as archive:
            for member in archive.getmembers():
                if not member.isfile():continue
                if member.name.startswith(GOLD+'/'):
                    name=member.name.removeprefix(GOLD+'/');target_root=a.data
                else:
                    name=member.name.removeprefix(RESULT+'/');target_root=a.output
                    if member.name=='status.json':name='h200_status.json'
                target=(target_root/name).resolve()
                if not target.is_relative_to(target_root.resolve()):raise ValueError('Invalid delivery path')
                target.parent.mkdir(parents=True,exist_ok=True)
                temporary=target.with_suffix(target.suffix+'.download')
                with archive.extractfile(member) as source:temporary.write_bytes(source.read())
                temporary.replace(target)
        (a.output/'delivery_verification.json').write_bytes(json.dumps(dict(**meta,remote_work=work,run_id=a.run_id),indent=2).encode())
        print(json.dumps(dict(output=str(a.output),verified_delivery_sha256=meta['sha256'])));return
    if not a.build_gold:
        manifest=json.loads((a.data/'manifest.json').read_text(encoding='utf-8'))
        if manifest['population']!=12418 or not manifest['require_model_inference_for_every_CVE']:
            raise ValueError('Full-population Gold is required')
    archive_path=Path(tempfile.gettempdir())/(a.run_id+'-inputs.tar.gz')
    code_manifest={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in FILES}
    reuse=False
    if archive_path.exists() and a.build_gold:
        with tarfile.open(archive_path,'r:gz') as archive:
            reuse=all(hashlib.sha256(archive.extractfile(name).read()).hexdigest()==expected for name,expected in code_manifest.items())
        if not reuse:raise ValueError('Run input code changed; use a new run ID')
    if not reuse:
        with tarfile.open(archive_path,'w:gz') as archive:
            for name in FILES:archive.add(ROOT/name,arcname=name)
            if not a.build_gold:archive.add(a.data,arcname=GOLD)
    incoming=REMOTE+'/incoming/'+a.run_id+'-inputs.tar.gz'
    upload(a.config,archive_path,incoming)
    script = """from pathlib import Path
import tarfile,shutil,subprocess,json,base64,hashlib
root=Path(__ROOT_PATH__);work=Path(__WORK_PATH__);work.mkdir(parents=True,exist_ok=False)
for name in ['src','tools']:
 shutil.copytree(root/'project'/name,work/name,ignore=shutil.ignore_patterns('__pycache__'))
with tarfile.open(__INPUT_ARCHIVE__,'r:gz') as archive:
 for member in archive.getmembers():
  if not (member.isfile() or member.isdir()):raise ValueError('Only files and directories allowed')
  target=(work/member.name).resolve()
  if not target.is_relative_to(work.resolve()):raise ValueError('Invalid input path')
  archive.extract(member,work)
for name in ['models','site','icsa']:(work/name).symlink_to(root/'project'/name,target_is_directory=True)
(work/'benchmark').mkdir(exist_ok=True)
(work/'results').mkdir()
(work/'results/item4_condition_clusters_v1').symlink_to(root/'project/results/item4_condition_clusters_v1',target_is_directory=True)
(work/'benchmark/item4_source_context_sft_v1').symlink_to(root/'project/benchmark/item4_source_context_sft_v1',target_is_directory=True)
manifest=__CODE_MANIFEST__
for name,h in manifest.items():assert hashlib.sha256((work/name).read_bytes()).hexdigest()==h,name
(work/'code_manifest.json').write_text(json.dumps(manifest,indent=2))
(work/'worker.py').write_bytes(base64.b64decode(__WORKER_BASE64__))
with (work/'worker.log').open('ab') as log:
 job=subprocess.Popen([str(root/'venv/bin/python'),'-u',str(work/'worker.py')],cwd=work,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
(work/'job.json').write_text(json.dumps({'pid':job.pid,'work':str(work)}))
print(json.dumps({'pid':job.pid,'work':str(work)}))
""".replace('__ROOT_PATH__',repr(REMOTE)).replace('__WORKER_BASE64__',repr(base64.b64encode(WORKER.encode()).decode())).replace('__WORK_PATH__',repr(work)).replace('__INPUT_ARCHIVE__',repr(incoming)).replace('__CODE_MANIFEST__',repr(code_manifest))
    print(execute(a.config,script))


if __name__=='__main__':main()
