"""Exercise actual shared-server inference; never fabricates operating facts."""
import json,time
from pathlib import Path
import requests

ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'results/operational_questionnaire_gpu_smoke.json'
result={'status':'running','operating_facts_fabricated':False,'started_at':time.time()}
def save():out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
save()
try:
    r=requests.post('http://127.0.0.1:8100/api/oc/questions',json={'product':'Satel Netco Design review',
        'simulation':True,'cves':[{'cve':'CVE-2026-101024','version_decided':False}]},timeout=900)
    r.raise_for_status();result['questionnaire']=r.json();save()
    # Empty answers are deliberate: real operator facts have not been supplied.
    r=requests.post('http://127.0.0.1:8100/api/oc/answers',json={'plan_id':result['questionnaire']['id'],'answers':{}},timeout=900)
    r.raise_for_status();result['review']=r.json();result['status']='completed'
except Exception as e:result.update(status='failed',error=str(e))
result['elapsed_seconds']=round(time.time()-result['started_at'],1);save()
print(json.dumps({'status':result['status'],'elapsed_seconds':result['elapsed_seconds'],
    'generation_status':[c['generation']['status'] for c in result.get('questionnaire',{}).get('cases',[])],
    'assessment_status':[s['operational_review']['assessment']['status'] for s in result.get('review',{}).get('statements',[])]}))
