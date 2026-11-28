"""Track this finite run and fetch/independently rescore its final artifacts."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tarfile
import time

from tools.common.ncp_api_transport import execute
from tools.common.ncp_transport import command

ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/'hysage-kubeconfig.yaml'
REMOTE='/home/irteam/data-vol1/ics-vex-migration-20261116/item4-extracted-ox-20261120-r1'
LOCAL=ROOT/'results/item4_extracted_ox_v3_20261120'
SUPPORT=Path('D:/ICS-VEX-support/results/item4_extracted_ox_v3_20261120')


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temporary.replace(path)


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def status():
    script='''from pathlib import Path
import json
w=Path(WORK);out=w/'results/item4_extracted_ox_v3'
pid=int((w/'worker.pid').read_text());p=Path('/proc')/str(pid)
old=w.parent/'item4-full-actual-20261120-v6/results/item4_full_actual_20261120'
state=json.loads((out/'status.json').read_text()) if (out/'status.json').exists() else dict(status='initializing')
state.update(worker_alive=p.exists() and b'run_item4_extracted_ox' in (p/'cmdline').read_bytes(),
    extracted_cves=len(list((old/'cves').glob('CVE-*.json'))),actual_evaluated_cves=len(list((out/'cves').glob('CVE-*.json'))))
state['extraction_status']=json.loads((old/'status.json').read_text())
producer_pid=int((old.parent.parent/'worker.pid').read_text())
producer=Path('/proc')/str(producer_pid)
state['extraction_process_alive']=producer.exists() and b'run_item4_full_actual' in (producer/'cmdline').read_bytes()
if not state['worker_alive'] and state.get('status')!='complete':state['log_tail']=(w/'worker.log').read_text(errors='replace')[-3500:]
print(json.dumps(state))
'''.replace('WORK',repr(REMOTE))
    result=json.loads(execute(CONFIG,script,timeout=45));write(LOCAL/'remote_status.json',result)
    return result


def fetch():
    script='''from pathlib import Path
import json,hashlib,tarfile
w=Path(WORK);out=w/'results/item4_extracted_ox_v3';data=w/'benchmark/item4_evaluation/extracted_ox_v3'
assert json.loads((out/'status.json').read_text())['status']=='complete'
archive=w/'extracted_ox_v3_delivery.tar.gz';paths=[]
for folder in [data,out,w/'results/mulval_cache']:
 for p in folder.rglob('*'):
  if p.is_file() and 'mulval_runs' not in p.parts and p.suffix!='.lock':paths.append(p)
paths += list((w/'src').rglob('*.py'))+[w/'tools/item4/run_item4_extracted_ox.py',w/'tools/item4/run_item4_full_actual.py',w/'transfer_manifest.json']
entries=[(p,p.relative_to(w).as_posix()) for p in paths]
# Retain the actual producer bytes, including failed raw generations. Its old
# five-case verdicts are provenance only, not the new O/X evaluation results.
producer=w.parent/'item4-full-actual-20261120-v6'
original=producer/'results/item4_full_actual_20261120'
for folder in ['cves','raw','requests']:
 for p in (original/folder).glob('*.json'):
  entries.append((p,'source_extraction_audit/'+folder+'/'+p.name))
for name in ['run_config.json','runtime_metadata.json','optimization_probe.json']:
 p=original/name
 if p.exists():entries.append((p,'source_extraction_audit/'+name))
config=json.loads((original/'run_config.json').read_text())
population=producer/'benchmark/item4_evaluation'
frozen_manifest=json.loads((population/'full_population_manifest.json').read_text())
for name in ['full_population_manifest.json',*frozen_manifest['artifacts']]:
 entries.append((population/name,'source_extraction_audit/frozen_population/'+name))
for name in config['code_sha256']:
 p=producer/name;assert hashlib.sha256(p.read_bytes()).hexdigest()==config['code_sha256'][name]
 entries.append((p,'source_extraction_audit/frozen_producer/'+name))
for name,expected in config.get('evaluation_code_sha256',{}).items():
 p=producer/'tools'/name;assert hashlib.sha256(p.read_bytes()).hexdigest()==expected
 entries.append((p,'source_extraction_audit/frozen_producer/tools/'+name))
manifest={name:hashlib.sha256(p.read_bytes()).hexdigest() for p,name in entries}
assert len(manifest)==len(entries)
(w/'delivery_manifest.json').write_text(json.dumps(manifest,indent=2))
with tarfile.open(archive,'w:gz',compresslevel=3,dereference=True) as tar:
 for p,name in entries:tar.add(p,arcname=name,recursive=False)
 tar.add(w/'delivery_manifest.json',arcname='delivery_manifest.json')
h=hashlib.sha256()
with archive.open('rb') as f:
 for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
receipt=dict(bytes=archive.stat().st_size,sha256=h.hexdigest(),files=len(entries))
temporary=w/'pack_receipt.json.tmp'
temporary.write_text(json.dumps(receipt));temporary.replace(w/'pack_receipt.json')
'''.replace('WORK',repr(REMOTE))
    # Packaging may exceed a transport request's timeout. Keep it remote and
    # observe its completion without interrupting a valid archive operation.
    launch='''from pathlib import Path
import json,subprocess,sys
w=Path(WORK)
assert json.loads((w/'results/item4_extracted_ox_v3/status.json').read_text())['status']=='complete'
receipt=w/'pack_receipt.json';pidfile=w/'pack.pid'
if not receipt.exists():
 alive=False
 if pidfile.exists():
  p=Path('/proc')/pidfile.read_text().strip()
  alive=p.exists() and b'pack_delivery.py' in (p/'cmdline').read_bytes()
 if not alive:
  code=w/'pack_delivery.py';code.write_text(SCRIPT)
  log=(w/'pack.log').open('ab')
  process=subprocess.Popen([sys.executable,'-B',str(code)],stdout=log,stderr=log,start_new_session=True)
  pidfile.write_text(str(process.pid))
print('packaging_started_or_already_available')
'''.replace('WORK',repr(REMOTE)).replace('SCRIPT',repr(script))
    execute(CONFIG,launch,timeout=45)
    probe='''from pathlib import Path
import json
w=Path(WORK);receipt=w/'pack_receipt.json'
if receipt.exists():print(json.dumps(dict(status='complete',receipt=json.loads(receipt.read_text()))))
else:
 p=Path('/proc')/(w/'pack.pid').read_text().strip()
 alive=p.exists() and b'pack_delivery.py' in (p/'cmdline').read_bytes()
 print(json.dumps(dict(status='running' if alive else 'failed',log_tail=(w/'pack.log').read_text(errors='replace')[-2000:] if not alive else '')))
'''.replace('WORK',repr(REMOTE))
    while True:
        try:packed=json.loads(execute(CONFIG,probe,timeout=45))
        except Exception as exc:
            print(json.dumps(dict(status='pack_transport_retry',error=str(exc))),flush=True)
            time.sleep(30);continue
        if packed['status']=='complete':receipt=packed['receipt'];break
        if packed['status']=='failed':raise RuntimeError(packed['log_tail'])
        print(json.dumps(dict(status='packaging_final_artifacts')),flush=True)
        time.sleep(30)
    SUPPORT.mkdir(parents=True,exist_ok=True);archive=SUPPORT/'delivery.tar.gz'
    partial=SUPPORT/'delivery.tar.gz.part'
    for attempt in range(3):
        try:
            print(json.dumps(dict(status='downloading_final_artifacts',bytes=receipt['bytes'],attempt=attempt+1)),flush=True)
            with partial.open('wb') as stream:
                subprocess.run(command(CONFIG)+['cat',REMOTE+'/extracted_ox_v3_delivery.tar.gz'],stdout=stream,check=True)
            assert sha(partial)==receipt['sha256'],'Downloaded archive hash mismatch'
            partial.replace(archive);break
        except Exception as exc:
            if attempt==2:raise
            print(json.dumps(dict(status='download_retry',error=str(exc))),flush=True)
            time.sleep(30)
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():assert m.isfile() and (SUPPORT/m.name).resolve().is_relative_to(SUPPORT.resolve())
        tar.extractall(SUPPORT)
    manifest=json.loads((SUPPORT/'delivery_manifest.json').read_bytes())
    for name,h in manifest.items():assert sha(SUPPORT/name)==h,name
    from src.item4.evaluation.operator_observation_benchmark import metrics
    out=SUPPORT/'results/item4_extracted_ox_v3';data=SUPPORT/'benchmark/item4_evaluation/extracted_ox_v3'
    predictions=[json.loads(s) for s in (out/'predictions.jsonl').open(encoding='utf-8')]
    references=[json.loads(s) for s in (data/'candidate_labels.jsonl').open(encoding='utf-8')]
    report=json.loads((out/'report.json').read_bytes())
    assert len({r['cve'] for r in predictions})==12418
    assert metrics(predictions,references)==report['all_cases']
    inputs=[json.loads(s) for s in (data/'inputs.jsonl').open(encoding='utf-8')]
    assert len(inputs)==len({r['id'] for r in inputs})==len(predictions)
    assert {r['id'] for r in inputs}=={r['id'] for r in predictions}
    assert not any(any(k in r for k in ['actual_affected','logic_consistency_only','label_method']) for r in inputs)
    from tools.item4.audit_item4_extracted_ox import audit
    independent_audit=audit(SUPPORT)
    write(LOCAL/'independent_audit.json',independent_audit)
    LOCAL.mkdir(parents=True,exist_ok=True)
    for name in ['report.json','protocol.json','status.json']:write(LOCAL/name,json.loads((out/name).read_bytes()))
    verification=dict(status='complete',population_cves=12418,cases=len(inputs),independent_rescore_passed=True,
        all_file_hashes_verified=True,archive=receipt,artifact_directory=str(SUPPORT),expert_review_complete=False)
    write(LOCAL/'verification.json',verification)
    write(data/'LOCAL_PROGRESS_POINTER.json',dict(status='complete',population_cves=12418,
        cases=len(inputs),full_population_evaluation_complete=True,
        local_verified_cves=12418,verification=str(LOCAL/'verification.json'),
        independent_audit=str(LOCAL/'independent_audit.json')))
    benchmark=ROOT/'benchmark/item4_evaluation';active=benchmark/'active_benchmark.json'
    previous=json.loads(active.read_bytes())
    if previous.get('version')!='item4-extracted-ox/3':
        history=benchmark/'active_benchmark_before_extracted_ox_v3.json'
        if not history.exists():write(history,previous)
    write(active,dict(version='item4-extracted-ox/3',directory='extracted_ox_v3',status='complete',
        population_cves=12418,cases=len(inputs),expert_review_complete=False,
        metric='TP/(TP+FP)>0.85',unknown_predicted_affected_blocks_primary_score=True,
        actual_service_decision_code=True,full_population_complete=True,
        report=str(LOCAL/'report.json'),verification=str(LOCAL/'verification.json'),
        previous_version='csaf_vex_v2',no_new_training_in_this_evaluation=True))
    readme=benchmark/'README.txt';text=readme.read_text(encoding='utf-8')
    marker='2026-11-20 CSAF 사유 및 전문가 검증 v2 개정'
    history=text[text.index(marker):] if marker in text else text
    introduction=('2026-11-20 실제 추출 조건·O/X/모름 기반 v3 전수 평가 완료\n'
        f'12,418개 CVE 전체·{len(inputs):,}개 합성 입력 조합을 실제 서비스 판정 코드와 MulVAL로 평가했습니다.\n'
        '최신 데이터: extracted_ox_v3/manifest.json\n'
        '방법: EXTRACTED_OX_V3_PROTOCOL.md\n'
        '결과 및 독립 재검산: results/item4_extracted_ox_v3_20261120/\n'
        '원문 기반 조건부 후보 라벨이며 전문가 검증과 실제 자산 정확도 검증은 미실시입니다.\n'
        '기존 affected 정밀도와 unknown 양성 보류 규칙을 유지했습니다.\n'
        '조건 미생성·검증 실패·제품 미연결 사례도 모집단에서 제외하지 않았습니다.\n'
        'population_ledger.json은 생성 시작 시의 고정 장부입니다. 완료 증거는 manifest·population_index·verification입니다.\n'
        '아래 문구는 이전 데이터 버전의 역사적 기록입니다.\n\n')
    readme.write_text(introduction+history,encoding='utf-8')
    print(json.dumps(verification,ensure_ascii=False),flush=True)
    return verification


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['status','watch','fetch']);args=p.parse_args()
    if args.action=='fetch':fetch();return
    if args.action=='status':print(json.dumps(status(),ensure_ascii=False));return
    while True:
        try:
            state=status()
        except Exception as exc:
            write(LOCAL/'monitor_error.json',dict(error=str(exc),at=time.time(),retrying=True))
            print(json.dumps(dict(status='transport_retry',error=str(exc),at=time.time())),flush=True)
            time.sleep(30)
            continue
        print(json.dumps(state,ensure_ascii=False),flush=True)
        if state.get('status')=='complete':fetch();return
        if not state.get('worker_alive'):
            write(LOCAL/'monitor_error.json',dict(error='OX worker stopped before full coverage',at=time.time(),retrying=False))
            raise RuntimeError('OX worker stopped before full coverage')
        if not state.get('extraction_process_alive') and state.get('extracted_cves',0)<12418:
            write(LOCAL/'monitor_error.json',dict(error='Source extraction stopped before full coverage',at=time.time(),retrying=False))
            raise RuntimeError('Source extraction stopped before full coverage')
        time.sleep(45)


if __name__=='__main__':main()
