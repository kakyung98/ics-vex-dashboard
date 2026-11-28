"""Isolated H200 contract/CUDA regression and full-population source audit.

Only enumerated source files are uploaded; no credentials, old labels or serving
files are replaced. Tiny fictional training tests are not real accuracy results.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.common.ncp_transport import execute

ROOT = Path(__file__).resolve().parents[3]
REMOTE = '/home/irteam/data-vol1/ics-vex-migration-20261116'
FILES = ['tools/item4/research/__init__.py', 'src/research/__init__.py', 'src/research/item4_stage1.py', 'src/item4/analysis/advisory_source_bundles.py', 'src/research/item4_stage1_contracts.py',
         'src/research/item4_stage1_evaluation.py', 'src/research/item4_stage1_spans.py', 'src/research/item4_stage1_bert.py',
         'src/research/reviewer_agreement.py', 'tools/item4/research/item4_stage1.py',
         'src/common/runtime/gpu_lease.py', 'src/common/runtime/training_progress_io.py',
         'tests/item4/test_item4_stage1.py', 'tests/item4/test_item4_stage1_spans.py']

WORKER = r'''
from pathlib import Path
import hashlib,json,os,subprocess,sys,time,traceback
work=Path(__file__).resolve().parent
root=Path('/home/irteam/data-vol1/ics-vex-migration-20261116')
source=root/'project';python=root/'venv/bin/python'
reuse_source_run=__SOURCE_RUN__
status=work/'status.json'
report={'status':'running','started_at':time.time(),'real_model_trained':False,
        'independent_semantic_accuracy_verified':False,'existing_service_modified':False}
def save():
 tmp=status.with_suffix('.tmp');tmp.write_text(json.dumps(report,indent=2));tmp.replace(status)
def run(stage,args,env=None):
 report['stage']=stage;save()
 with (work/(stage+'.log')).open('w') as log:
  result=subprocess.run([str(python),*map(str,args)],cwd=work,stdout=log,stderr=subprocess.STDOUT,env=env)
 if result.returncode:raise RuntimeError(stage+' failed: '+str(result.returncode))
try:
 save()
 gpu=json.loads(subprocess.check_output([str(python),'-c',
  "import torch,json; print(json.dumps({'cuda':torch.cuda.is_available(),'name':torch.cuda.get_device_name(0) if torch.cuda.is_available() else None}))"]))
 if not gpu['cuda'] or 'H200' not in gpu['name']:raise RuntimeError('H200 required')
 report['gpu']=gpu
 lease=source/'results/operational_role_finetune_v2/gpu_lease.json'
 if lease.exists():
  state=json.loads(lease.read_text())
  if state.get('active'):
   for key in ('pid','child_pid'):
    pid=state.get(key)
    if isinstance(pid,int) and (Path('/proc')/str(pid)).exists():raise RuntimeError('Existing GPU queue active')
 env=dict(os.environ,ITEM4_TEST_DEVICE='cuda',TOKENIZERS_PARALLELISM='false')
 run('tests',['-m','pytest','tests/item4/test_item4_stage1.py','tests/item4/test_item4_stage1_spans.py','-q','--junitxml=tests.xml'],env)
 report['cuda_tiny_training_regression']='passed; random tiny fictional fixture, not production training or accuracy'
 index=source/'benchmark/icsa-cpe-synthetic sbom/index.json'
 report['population_index_sha256']=hashlib.sha256(index.read_bytes()).hexdigest()
 if reuse_source_run:
  import shutil
  previous=root/'stage1-runs'/reuse_source_run
  prior=json.loads((previous/'status.json').read_text())
  if prior.get('population_index_sha256')!=report['population_index_sha256']:raise RuntimeError('Reused source population changed')
  if not json.loads((previous/'source_audit.json').read_text())['passed']:raise RuntimeError('Prior source audit failed')
  shutil.copyfile(previous/'bundle.json',work/'bundle.json')
  report['source_bundle_reused_from']=reuse_source_run;save()
 else:
  run('prepare',['tools/item4/research/item4_stage1.py','prepare','--input',source/'icsa/csaf','--population',index,
                 '--expected-advisories',index,'--output','bundle.json'])
 run('audit',['tools/item4/research/item4_stage1.py','audit','--bundle','bundle.json','--output','source_audit.json'])
 run('propose',['tools/item4/research/item4_stage1.py','propose','--bundle','bundle.json','--output','candidates.json'])
 (work/'reviews.json').write_text('[]')
 run('export',['tools/item4/research/item4_stage1.py','export','--bundle','bundle.json','--extraction','candidates.json',
               '--reviews','reviews.json','--output','export.json'])
 run('schemas',['tools/item4/research/item4_stage1.py','schemas','--output','schemas'])
 sys.path.insert(0,str(work))
 from src.research.item4_stage1 import extraction_report
 b=json.loads((work/'bundle.json').read_text());e=json.loads((work/'candidates.json').read_text());x=json.loads((work/'export.json').read_text())
 report['extraction']=extraction_report(b,e,x)
 if report['extraction']['population']!=12418:raise RuntimeError('Expected full 12418-CVE population')
 # Blinded source-only templates. No fabricated human annotations or Gold.
 import random
 docs=sorted({s['source_id'] for s in b['segments'] if s['source_role']=='cve_description'})
 selected=set(random.Random(42).sample(docs,min(100,len(docs))))
 annotation=[];bydoc={d['id']:d for d in b['documents']}
 for s in b['segments']:
  if s['source_id'] not in selected:continue
  doc=bydoc[s['source_id']]
  annotation.append(dict(id=s['id'],source_id=s['source_id'],source_type='ICSA',group_id=doc['advisory_id'],
   source_file=doc['filename'],source_document_sha256=doc['document_sha256'],source_json_pointer=s['source_json_pointer'],
   text=s['text'],text_sha256=s['text_sha256'],cves=s['cves'],product_refs=s['product_ids'],
   annotation_complete=False,annotator=None,annotation_origin=None,model_predictions_seen=False,spans=[]))
 with (work/'pilot_annotation_template.jsonl').open('w') as f:
  for row in annotation:f.write(json.dumps(row,ensure_ascii=False)+'\n')
 from src.research.item4_stage1_evaluation import training_readiness
 ready,_=training_readiness({k:work/'pilot_annotation_template.jsonl' for k in ('train','dev','test')})
 readiness=dict(ready=ready['ready'],documents=ready['documents'],error_count=len(ready['errors']),
  error_examples=ready['errors'][:5],reason='No independent human-annotated train/dev/test corpus supplied',
  training_device_policy=ready['training_device_policy'])
 (work/'training_readiness.json').write_text(json.dumps(readiness,indent=2))
 report['training_readiness']=readiness;report['pilot_documents']=len(selected);report['pilot_segments']=len(annotation)
 report['status']='complete';report['stage']='complete'
except Exception:
 report['status']='failed';report['error']=traceback.format_exc()
finally:
 report['finished_at']=time.time();save()
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--run-id', required=True)
    p.add_argument('--reuse-source-run', help='Reuse an immutable source bundle, then audit its original sources again')
    p.add_argument('--fetch', action='store_true', help='Fetch status, test evidence and pilot template from an existing run')
    args = p.parse_args()
    import re
    if not re.fullmatch(r'[A-Za-z0-9_-]+', args.run_id): raise ValueError('Invalid run ID')
    if args.reuse_source_run and not re.fullmatch(r'[A-Za-z0-9_-]+', args.reuse_source_run): raise ValueError('Invalid source run ID')
    dest = REMOTE + '/stage1-runs/' + args.run_id
    if args.fetch:
        names = ['status.json', 'code_manifest.json', 'tests.xml', 'tests.log', 'source_audit.json',
                 'training_readiness.json', 'pilot_annotation_template.jsonl']
        script = 'from pathlib import Path\nimport json,base64,hashlib\np=Path(' + repr(dest) + ')\n'
        script += 'names=' + repr(names) + '\nresult={}\n'
        script += 'for name in names:\n f=p/name\n if f.exists():\n  raw=f.read_bytes();result[name]={"base64":base64.b64encode(raw).decode(),"sha256":hashlib.sha256(raw).hexdigest()}\nprint(json.dumps(result))'
        result = json.loads(execute(args.config, script))
        out = ROOT/'results/item4_stage1'/args.run_id
        out.mkdir(parents=True, exist_ok=True)
        for name, record in result.items():
            raw = base64.b64decode(record['base64'])
            if hashlib.sha256(raw).hexdigest() != record['sha256']: raise ValueError('Artifact transfer hash mismatch')
            path = out/name
            if path.exists() and name != 'status.json' and path.read_bytes() != raw:
                raise ValueError('Immutable result already exists with different bytes: ' + name)
            path.write_bytes(raw)
        print(json.dumps(dict(fetched=list(result), output=str(out))))
        return
    payload = {n:base64.b64encode((ROOT/n).read_bytes()).decode() for n in FILES}
    manifest = {n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in FILES}
    worker = WORKER.replace('__SOURCE_RUN__', repr(args.reuse_source_run))
    payload['worker.py'] = base64.b64encode(worker.encode()).decode()
    manifest['worker.py'] = hashlib.sha256(worker.encode()).hexdigest()
    script = '''from pathlib import Path
import base64,hashlib,json,subprocess
work=Path(__DEST__)
work.mkdir(parents=True,exist_ok=False)
for name,value in json.loads(__PAYLOAD__).items():
 p=work/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode(value))
for folder in ['src','tools']:(work/folder/'__init__.py').write_text('')
manifest=json.loads(__MANIFEST__)
assert all(hashlib.sha256((work/n).read_bytes()).hexdigest()==v for n,v in manifest.items())
(work/'code_manifest.json').write_text(json.dumps(manifest,indent=2))
log=(work/'worker.log').open('wb')
job=subprocess.Popen([__REMOTE_ROOT__+'/venv/bin/python',str(work/'worker.py')],cwd=work,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
print(json.dumps(dict(work=str(work),pid=job.pid,code_sha256=manifest)))
'''.replace('__DEST__', repr(dest)).replace('__PAYLOAD__', repr(json.dumps(payload))).replace('__MANIFEST__', repr(json.dumps(manifest))).replace('__REMOTE_ROOT__', repr(REMOTE))
    result = json.loads(execute(args.config, script))
    out = ROOT/'results/item4_stage1'/args.run_id
    out.mkdir(parents=True, exist_ok=False)
    (out/'job.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__': main()
