"""Actual local HTTP workflow smoke, no external APIs or fabricated GPU results."""

from sbom_paths import public_sbom_file
from datetime import datetime,timezone
import json,time,sys
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json

def main():
    folder=ROOT/'results/identity_evidence_v3_smoke';folder.mkdir(exist_ok=True)
    state={'phase':'starting','started_at':datetime.now(timezone.utc).isoformat(),'external_model_api_calls':0}
    atomic_json(folder/'status.json',state)
    def run(name,sbom,mode):
        sbom=json.loads(json.dumps(sbom));sbom.pop('vulnerabilities',None)
        response=requests.post('http://127.0.0.1:8100/api/cve-match/jobs',json={'sbom':sbom,'agent_mode':mode,'lookup_mode':'local'},timeout=20)
        response.raise_for_status();jid=response.json()['id'];start=time.time()
        while time.time()-start<900:
            response=requests.get('http://127.0.0.1:8100/api/cve-match/jobs/'+jid,timeout=20);response.raise_for_status();job=response.json()
            state.update(phase=name,job_id=jid,progress=job.get('progress'));atomic_json(folder/'status.json',state)
            if job['status'] in {'completed','failed'}:
                atomic_json(folder/(name+'.json'),job)
                if job['status']=='failed':raise RuntimeError(job.get('error'))
                print(name,json.dumps(job['result']['summary']),flush=True);return job
            time.sleep(2)
        raise TimeoutError(name)
    try:
        supplied=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8'))
        cpu=run('supplied_easyio_cpu',supplied,'evidence')
        gpu=run('qwen_base_ranking',{'bomFormat':'CycloneDX','components':[{'name':'curl','version':'NOASSERTION','supplier':{'name':'Haxx'}}]},'evidence_llm')
        a=gpu['result']['components'][0]['l2']['agent']
        state.update(phase='complete',actual_qwen_response_recorded=bool(a and 'raw' in a),
            ranking_status=a.get('status') if a else None,independent_accuracy_evaluated=False,
            input_vulnerabilities_used_as_answers=False)
    except Exception as e:state.update(phase='failed',error=str(e))
    atomic_json(folder/'status.json',state)

if __name__=='__main__':main()
