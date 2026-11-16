"""Download small completed H200 evaluation reports; raw predictions remain on NCP."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.ncp_transport import execute
job=json.loads((ROOT/'results/cloud_migration/h200_full_evaluation_job.json').read_text(encoding='utf-8'))
script='''from pathlib import Path
import json,sqlite3
r=Path(RUN)
state=json.loads((r/'status.json').read_text())
assert state['status']=='complete','Evaluation is still running or failed'
project=r.parents[1]
canonical={json.loads(x)['cve'] for x in (project/'benchmark/cve_population_12418_v1/labels.jsonl').open()}
assert len(canonical)==12418
checks={}
for name,file,expected_rows in [('item3','item3_predictions.sqlite3',12418),('item4','predictions.sqlite3',24678)]:
 with sqlite3.connect((r/name/file).as_uri()+'?mode=ro',uri=True) as db:
  cves={x[0] for x in db.execute('select distinct cve from predictions')}
  count=db.execute('select count(*) from predictions').fetchone()[0]
 assert cves==canonical and count==expected_rows
 checks[name]=dict(CVEs=len(cves),rows=count,missing_CVEs=0,extra_CVEs=0)
third=json.loads((r/'item3/item3_precision_report.json').read_text())
fourth=json.loads((r/'item4/precision_report.json').read_text())
assert third['cache_statistics_before']['cached_packets']==0
assert third['cache_statistics_after']['actual_llm_requests']>0
assert fourth['actual_model_requests']==14712
checks['fresh_inference']=dict(initial_item3_cache=third['cache_statistics_before'],
 item3_actual_model_requests=third['cache_statistics_after']['actual_llm_requests'],item4_actual_model_requests=fourth['actual_model_requests'])
(r/'population_integrity.json').write_text(json.dumps(checks,indent=2))
summary=json.loads((r/'summary.json').read_text())
summary['elapsed_seconds']={k:v['finished_unix']-v['started_unix'] for k,v in state['stages'].items()}
summary['elapsed_seconds']['total']=state['finished_unix']-state['started_unix']
summary['population_integrity']=checks
(r/'summary.json').write_text(json.dumps(summary,indent=2))
files=['status.json','protocol.json','summary.json','item3/fresh_inference_protocol.json','item3/run_config.json',
 'item3/status.json','item3/item3_precision_report.json','item3/validation_report.json',
 'item4/fresh_inference_protocol.json','item4/run_config.json','item4/status.json','item4/precision_report.json','item4/reverification.json','population_integrity.json']
print(json.dumps({name:json.loads((r/name).read_text()) for name in files}))
'''.replace('RUN',repr(job['run_root']))
if __name__=='__main__':
    data=json.loads(execute(Path.home()/'Downloads/hysage-kubeconfig.yaml',script))
    out=ROOT/'results'/Path(job['run_root']).name
    out.mkdir(exist_ok=True)
    for name,value in data.items():
        dest=out/name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(json.dumps(value,indent=2),encoding='utf-8')
    print(json.dumps(dict(summary=str(out/'summary.json'),status=data['summary.json']['status'],
        item3_precision_lower_bound=data['summary.json']['item3']['deduplicated_full_output_micro']['precision_lower_bound_percent'],
        item4_heldout=data['summary.json']['item4']['evaluation'])))
