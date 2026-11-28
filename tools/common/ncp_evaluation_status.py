"""Read compact progress from the current remote full-population evaluation."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.common.ncp_transport import execute
job=ROOT/'results/cloud_migration/h200_full_evaluation_job.json'
config=json.loads(job.read_text(encoding='utf-8'))
script='''from pathlib import Path
import json,sqlite3,time,subprocess
r=Path(RUN)
d=json.loads((r/'status.json').read_text())
result=dict(run=str(r),status=d,elapsed_seconds=round(time.time()-d['started_unix'],1))
for name in ['item3','item4']:
 p=r/name/'status.json'
 if p.exists():result[name]=json.loads(p.read_text())
 log=r/(name+'.log')
 if log.exists() and d.get('stages',{}).get(name,{}).get('status')!='complete':
  lines=log.read_text(errors='replace').splitlines()
  result[name+'_log_tail']='\\n'.join(lines[-3:])[-1700:]
 q=r/name/('item3_predictions.sqlite3' if name=='item3' else 'predictions.sqlite3')
 if q.exists():
  with sqlite3.connect(q.as_uri()+'?mode=ro',uri=True) as db:
   try:
    result[name+'_committed_rows']=db.execute('select count(*) from predictions').fetchone()[0]
    counts=dict(db.execute('select cve,count(*) from predictions group by cve'))
    if name=='item4':
     expected={x['cve']:len(x['cases']) for x in map(json.loads,(r.parents[1]/'benchmark/item4_source_context_gold_v2/cve_index.jsonl').open())}
     result[name+'_completed_CVEs']=sum(n==expected[c] for c,n in counts.items())
    else:result[name+'_completed_CVEs']=len(counts)
   except sqlite3.OperationalError:pass
result['GPU']=subprocess.check_output(['nvidia-smi','--query-gpu=utilization.gpu,memory.used','--format=csv,noheader'],text=True).strip()
if d['status']=='failed':result['queue_log']=r.with_suffix('.queue.log').read_text()[-2500:]
print(json.dumps(result))
'''.replace('RUN',repr(config['run_root']))
data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
(ROOT/'results/cloud_migration/h200_latest_progress.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps(data))
