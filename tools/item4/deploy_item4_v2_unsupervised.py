"""Deploy and track an isolated real training/evaluation run on the H200."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import argparse
import hashlib
import json
import tarfile
import time
import subprocess

from tools.common.ncp_api_transport import execute,upload_file

ROOT=Path(__file__).resolve().parents[2]
MIGRATION='/home/irteam/data-vol1/ics-vex-migration-20261116'
WORK=MIGRATION+'/item4-csaf-v2-unsupervised-20261120-r1'
OLD=MIGRATION+'/item4-full-actual-20261120-v6'
CONFIG=ROOT/'hysage-kubeconfig.yaml'
LOCAL=ROOT/'results/item4_v2_unsupervised_20261120'
DATA=ROOT/'benchmark/item4_evaluation/csaf_vex_v2'


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
    return h.hexdigest()


def deploy():
    LOCAL.mkdir(parents=True,exist_ok=True)
    files={}
    for name in ['training/corpus.jsonl','advisory_split.json','inputs.jsonl',
                 'sources/cve_evidence.jsonl','candidate_labels.jsonl','manifest.json']:
        files['benchmark/item4_evaluation/csaf_vex_v2/'+name]=DATA/name
    for name in ['tools/item4/run_item4_v2_unsupervised.py','src/item4/evaluation/synthetic_vex_benchmark.py',
                 'src/common/runtime/training_progress_io.py','src/common/runtime/safetensors_loading.py']:
        files[name]=ROOT/name
    marker=json.loads((ROOT/'models/precision_roles_qwen25_14b_v1/training_complete.json').read_bytes())
    manifest=dict(schema='item4-v2-unsupervised-run/1',seed=20261120,population_cves=12418,
        cases=86926,train_icsa=2717,epochs=1,checkpoint_selection='fixed_final_one_pass',
        lora=dict(rank=8,alpha=16,targets=['q_proj','v_proj']),
        training_objective='Unlabeled next-token prediction, all nonpadding tokens',
        data_sha256={name:sha(DATA/name) for name in ['training/corpus.jsonl','advisory_split.json',
            'inputs.jsonl','sources/cve_evidence.jsonl','candidate_labels.jsonl','manifest.json']},
        code_sha256={name:sha(path) for name,path in files.items() if name.endswith('.py')},
        original_base_files_sha256=marker['base_files_sha256'],
        evaluation_method='Direct trained-model seven-way bounded next-token evidence classification; not production MulVAL pipeline',
        metric='TP/(TP+FP)>0.85, unknown-positive blocking, candidate reference only',
        expert_review_deferred=True)
    (LOCAL/'run_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (LOCAL/'base_pin.json').write_text(json.dumps(marker['base_files_sha256'],indent=2)+'\n',encoding='utf-8')
    files['run_manifest.json']=LOCAL/'run_manifest.json';files['base_pin.json']=LOCAL/'base_pin.json'
    archive=Path('D:/ICS-VEX-support/task-temp/item4_v2_unsupervised_transfer.tar.gz')
    archive.parent.mkdir(parents=True,exist_ok=True)
    transfer={name:sha(path) for name,path in files.items()}
    (LOCAL/'transfer_manifest.json').write_text(json.dumps(transfer,indent=2)+'\n',encoding='utf-8')
    with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
        for name,path in files.items():tar.add(path,arcname=name,recursive=False)
        tar.add(LOCAL/'transfer_manifest.json',arcname='transfer_manifest.json')
    upload_file(CONFIG,archive,WORK+'/incoming.tar.gz',timeout=60)
    script='''from pathlib import Path
import tarfile,json,hashlib
w=Path(WORK)
if (w/'controller.pid').exists():raise RuntimeError('Run exists; do not overwrite')
with tarfile.open(w/'incoming.tar.gz') as t:
 for m in t.getmembers():
  if not (w/m.name).resolve().is_relative_to(w.resolve()):raise ValueError('Unsafe archive')
 t.extractall(w)
for name,h in json.loads((w/'transfer_manifest.json').read_text()).items():
 assert hashlib.sha256((w/name).read_bytes()).hexdigest()==h,name
print(json.dumps(dict(deployed=str(w),verified_files=len(json.loads((w/'transfer_manifest.json').read_text())))))
'''.replace('WORK',repr(WORK))
    print(execute(CONFIG,script,timeout=45))


CONTROLLER='''from pathlib import Path
import subprocess,os,json,time,signal,hashlib
w=Path(WORK);r=Path(MIGRATION);old=Path(OLD)
status=w/'pipeline_status.json'
def put(**kw):
 value=json.loads(status.read_text()) if status.exists() else {}
 value.update(kw);tmp=status.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2));tmp.replace(status)
def command(pid):
 p=Path('/proc')/str(pid)/'cmdline'
 return p.read_bytes() if p.exists() else b''
try:
 put(status='running',stage='preserving_v1_checkpoint',started_at=time.time())
 pid=int((old/'worker.pid').read_text())
 oldstatus=old/'results/item4_full_actual_20261120/status.json'
 if b'tools.item4.run_item4_full_actual' not in command(pid):raise RuntimeError('Old worker identity changed')
 backup=json.loads(oldstatus.read_text());backup['checkpoint_files']=len(list((oldstatus.parent/'cves').glob('CVE-*.json')))
 (w/'v1_pause_snapshot.json').write_text(json.dumps(dict(pid=pid,old_work=str(old),status=backup),indent=2))
 os.kill(pid,signal.SIGTERM)
 for i in range(120):
  if b'tools.item4.run_item4_full_actual' not in command(pid):break
  time.sleep(1)
 else:raise RuntimeError('Old worker did not release GPU after SIGTERM; no force kill')
 if list((oldstatus.parent/'cves').glob('CVE-*.json')):
  backup['status']='suspended_for_v2_training';backup['suspended_at']=time.time()
  oldstatus.write_text(json.dumps(backup,indent=2))
 env=dict(os.environ,HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONUNBUFFERED='1',
     ICSVEX_MIGRATION_ROOT=str(r),TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4')
 python=str(r/'venv/bin/python')
 common=['--data',str(w/'benchmark/item4_evaluation/csaf_vex_v2'),'--run',str(w),'--base',str(r/'base_model')]
 for phase in ['train','evaluate']:
  marker=w/('adapter/training_complete.json' if phase=='train' else 'evaluation/report.json')
  if marker.exists():continue
  put(stage=phase,updated_at=time.time())
  with (w/(phase+'.log')).open('a') as log:
   child=subprocess.Popen([python,'-B','-u','-m','tools.item4.run_item4_v2_unsupervised',phase,*common],cwd=w,env=env,stdout=log,stderr=subprocess.STDOUT)
   (w/(phase+'.pid')).write_text(str(child.pid));rc=child.wait()
  if rc:raise RuntimeError(phase+' exited '+str(rc))
 put(status='complete',stage='scored',finished_at=time.time())
except BaseException:
 import traceback
 put(status='failed',stage='needs_recovery',error=traceback.format_exc(),finished_at=time.time())
finally:
 # Resume the preserved v1 job only after the new GPU child has exited.
 pid=int((old/'worker.pid').read_text()) if (old/'worker.pid').exists() else None
 if pid is not None and b'tools.item4.run_item4_full_actual' not in command(pid):
  env=dict(os.environ,ICSVEX_MIGRATION_ROOT=str(r),LOCALAPPDATA=str(old/'runtime'),
      HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',PYTHONUNBUFFERED='1')
  cc=r/'item4-vllm-venv/bin/item4-cc';cxx=r/'item4-vllm-venv/bin/item4-cxx'
  if cc.is_file():env['CC']=str(cc)
  if cxx.is_file():env['CXX']=str(cxx)
  env.pop('ICS_PREREQUISITE_LLM_URL',None);env.pop('ICS_PREREQUISITE_LLM_MODEL',None)
  with (old/'worker.log').open('a') as log:
   p=subprocess.Popen([str(r/'venv/bin/python'),'-B','-u','-m','tools.item4.run_item4_full_actual',
       '--engine','hf_xgrammar_compact_cached','--batch-size','64','--threads','128'],cwd=old,env=env,
       stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  (old/'worker.pid').write_text(str(p.pid));put(v1_resumed_pid=p.pid)
'''


def start():
    script=CONTROLLER.replace('Path(WORK)','Path('+repr(WORK)+')').replace('Path(MIGRATION)','Path('+repr(MIGRATION)+')').replace('Path(OLD)','Path('+repr(OLD)+')')
    (LOCAL/'remote_controller.py').write_text(script,encoding='utf-8')
    upload_file(CONFIG,LOCAL/'remote_controller.py',WORK+'/controller.py',timeout=30)
    launcher='''from pathlib import Path
import subprocess,os,json
w=Path(WORK);r=Path(MIGRATION)
p=w/'controller.pid'
if p.exists():
 try:os.kill(int(p.read_text()),0)
 except ProcessLookupError:pass
 else:raise RuntimeError('Controller already running')
with (w/'controller.log').open('a') as log:
 c=subprocess.Popen([str(r/'venv/bin/python'),'-u',str(w/'controller.py')],cwd=w,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
p.write_text(str(c.pid));print(json.dumps(dict(started=True,controller_pid=c.pid,work=str(w))))
'''.replace('Path(WORK)','Path('+repr(WORK)+')').replace('Path(MIGRATION)','Path('+repr(MIGRATION)+')')
    print(execute(CONFIG,launcher,timeout=25))


def status():
    script='''from pathlib import Path
import json,os
w=Path(WORK);out={}
for name in ['pipeline_status.json','training/status.json','evaluation/status.json','training/failure.json','evaluation/failure.json']:
 p=w/name
 if p.exists():out[name]=json.loads(p.read_text())
if any(v.get('status')=='failed' for v in out.values()):
 for name in ['train','evaluate']:
  p=w/(name+'.log')
  if p.exists():out[name+'_log_tail']=p.read_text(errors='replace')[-4500:]
print(json.dumps(out))
'''.replace('Path(WORK)','Path('+repr(WORK)+')')
    raw=execute(CONFIG,script,timeout=30)
    (LOCAL/'remote_status.json').write_text(raw,encoding='utf-8')
    print(raw)


def fetch():
    script='''from pathlib import Path
import json,tarfile,hashlib
w=Path(WORK)
assert json.loads((w/'pipeline_status.json').read_text())['status']=='complete','Run is not complete'
files=[]
for name in ['adapter','training/train_config.json','training/status.json','evaluation',
             'pipeline_status.json','v1_pause_snapshot.json','run_manifest.json','base_pin.json',
             'train.log','evaluate.log','controller.log','evaluation_protocol.json',
             'training/train_worker_snapshot.py','tools/item4/run_item4_v2_unsupervised.py',
             'tools/item4/evaluate_item4_v2_prefix.py','controller.py','speed_controller.py']:
 p=w/name
 if p.is_dir():files.extend(x for x in p.rglob('*') if x.is_file())
 elif p.is_file():files.append(p)
manifest={p.relative_to(w).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(w/'delivery_manifest.json').write_text(json.dumps(manifest,indent=2))
archive=w/'delivery.tar.gz'
with tarfile.open(archive,'w:gz',compresslevel=3) as tar:
 for p in files:tar.add(p,arcname=p.relative_to(w).as_posix(),recursive=False)
 tar.add(w/'delivery_manifest.json',arcname='delivery_manifest.json')
print(json.dumps(dict(bytes=archive.stat().st_size,sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),files=len(files))))
'''.replace('Path(WORK)','Path('+repr(WORK)+')')
    receipt=json.loads(execute(CONFIG,script,timeout=45))
    from tools.common.ncp_transport import command
    destination=Path('D:/ICS-VEX-support/results/item4_v2_unsupervised_20261120')
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/'delivery.tar.gz'
    with archive.open('wb') as f:
        subprocess.run(command(CONFIG)+['cat',WORK+'/delivery.tar.gz'],stdout=f,check=True,timeout=120)
    if sha(archive)!=receipt['sha256']:raise ValueError('Delivery archive hash mismatch')
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():
            if not (destination/m.name).resolve().is_relative_to(destination.resolve()) or not (m.isfile() or m.isdir()):
                raise ValueError('Unsafe delivery member')
        tar.extractall(destination)
    delivered=json.loads((destination/'delivery_manifest.json').read_text())
    for name,expected in delivered.items():
        if sha(destination/name)!=expected:raise ValueError('Delivered file changed: '+name)
    frozen_run=json.loads((destination/'run_manifest.json').read_text())
    for name,expected in frozen_run['data_sha256'].items():
        if sha(DATA/name)!=expected:raise ValueError('Local benchmark drifted from executed inputs: '+name)
    from src.item4.evaluation.synthetic_vex_benchmark import affected_precision
    prediction_rows=list(map(json.loads,(destination/'evaluation/predictions.jsonl').open()))
    predictions={r['id']:r for r in prediction_rows}
    if len(prediction_rows)!=len(predictions):raise ValueError('Duplicate delivered prediction IDs')
    candidates={r['id']:dict(r,actual_affected=r['candidate_actual_affected']) for r in
        map(json.loads,(DATA/'candidate_labels.jsonl').open(encoding='utf-8'))}
    metric=affected_precision(predictions,candidates)
    report=json.loads((destination/'evaluation/report.json').read_text())
    assert sha(DATA/'candidate_labels.jsonl')==report['candidate_labels_sha256']
    if report['all_cases']!=metric:raise ValueError('Independent local rescore differs')
    if len(predictions)!=86926 or len({r['cve'] for r in predictions.values()})!=12418:
        raise ValueError('Delivered population incomplete')
    from collections import Counter
    assert set(Counter(r['cve'] for r in prediction_rows).values())=={7}
    assert all(r['cve']==candidates[key]['cve'] for key,r in predictions.items())
    training=json.loads((destination/'adapter/training_complete.json').read_text())
    config=json.loads((destination/'training/train_config.json').read_text())
    if set(config['coverage']['ids'])!=set(json.loads((DATA/'advisory_split.json').read_bytes())['train']):
        raise ValueError('Training coverage differs from the frozen 70% split')
    assert training['initial_trainable_sha256']!=training['final_trainable_sha256']
    assert training['optimizer_updates']>0 and training['heldout_loaded'] is False and training['synthetic_labels_loaded'] is False
    assert all(r.get('model_inference') is True and len(r['choice_logits'])==7 for r in predictions.values())
    preserved=[]
    prediction_bytes=(destination/'evaluation/predictions.jsonl').read_bytes()
    for segment_path in sorted((destination/'evaluation/segments').glob('*/segment.json')):
        segment=json.loads(segment_path.read_text())
        prefix=prediction_bytes[:segment['predictions_prefix_bytes']]
        assert hashlib.sha256(prefix).hexdigest()==segment['predictions_prefix_sha256']
        preserved.append(segment)
    from tools.item4.run_item4_v2_unsupervised import CHOICES
    for r in predictions.values():
        choice=max(range(7),key=lambda i:r['choice_logits'][i])
        status,just=CHOICES[choice]
        assert r['raw_digit']==str(choice) and r['status']==status and r['justification']==just
    cohort={fold:affected_precision({k:predictions[k] for k,g in candidates.items() if g['fold']==fold},
        {k:g for k,g in candidates.items() if g['fold']==fold}) for fold in ['train_context','evaluation']}
    (LOCAL/'cohort_metrics.json').write_text(json.dumps(dict(per_advisory_cohort=cohort,
        includes_train_related_cves=True,icsa_split_is_not_cve_disjoint=True),indent=2)+'\n',encoding='utf-8')
    for name,path in [('report.json',destination/'evaluation/report.json'),
                      ('training_complete.json',destination/'adapter/training_complete.json'),
                      ('train_config.json',destination/'training/train_config.json'),
                      ('pipeline_status.json',destination/'pipeline_status.json')]:
        (LOCAL/name).write_bytes(path.read_bytes())
    result=dict(status='complete',population_cves=12418,cases=86926,train_icsa=2717,
        all_cases=metric,independent_rescore_passed=True,artifact_hashes_verified=len(delivered),
        archive_sha256=receipt['sha256'],archive_bytes=receipt['bytes'],artifact_directory=str(destination),
        trained_adapter_path=str(destination/'adapter'),expert_review_complete=False,
        model_weights_changed=True,token_coverage=config['coverage']['token_count'],
        optimizer_updates=training['optimizer_updates'],preserved_execution_segments=preserved,
        speed_changes='Physical batching and length bucketing only; saved prediction prefixes verified byte-for-byte')
    pipeline=json.loads((destination/'pipeline_status.json').read_text())
    result['total_pipeline_seconds']=pipeline['finished_at']-pipeline['started_at']
    result['training_seconds']=training['elapsed_seconds']
    result['evaluation_wall_seconds_including_resource_changes']=result['total_pipeline_seconds']-training['elapsed_seconds']
    (LOCAL/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['deploy','start','status','fetch'])
    a=p.parse_args();globals()[a.action]()
