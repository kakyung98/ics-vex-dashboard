from pathlib import Path
import requests,json,time
out=Path('results/operational_activation_smoke');out.mkdir(exist_ok=True)
b='http://127.0.0.1:8100'
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,ensure_ascii=False,indent=2),encoding='utf-8')
def post(p,d=None):
 r=requests.post(b+p,json=d,timeout=1200);r.raise_for_status();return r.json()
try:
 save('status',{'phase':'starting','started_at':time.time()})
 save('models',requests.get(b+'/api/vex-review/models',timeout=30).json())
 review=post('/api/item4/start',{'cves':[{'cve':'CVE-2026-64893'}]});save('review',review)
 save('status',{'phase':'questions','review_id':review['review_id']})
 plan=post('/api/item4/'+review['review_id']+'/questions');save('questions',plan)
 save('status',{'phase':'assessment','review_id':review['review_id']})
 result=post('/api/item4/'+review['review_id']+'/answers',{'plan_id':plan['id'],'answers':{},'component_facts':{}});save('answers',result)
 save('status',{'phase':'complete','generation':plan['cases'][0]['generation']['status'],'external_api_calls':0})
except Exception as e:
 save('status',{'phase':'failed','error':str(e)});raise

