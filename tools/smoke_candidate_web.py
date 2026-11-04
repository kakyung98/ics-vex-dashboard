"""Exercise the real GPU job handlers in-process, without browser/network access."""

from sbom_paths import public_sbom_file
import json
from pathlib import Path
import sys
import time
import argparse

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from fastapi.testclient import TestClient
from src.api_server import app


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--easyio',action='store_true')
    args=parser.parse_args()
    client=TestClient(app)
    sbom=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8')) if args.easyio else {
        'bomFormat':'CycloneDX','components':[{'name':'curl','version':'7.23.1'}]}
    response=client.post('/api/cve-match/jobs',json={
        'sbom':sbom,
        'agent_mode':'tuned','lookup_mode':'local'})
    assert response.status_code==202,response.text
    job_id=response.json()['id'];deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        job=client.get('/api/cve-match/jobs/'+job_id).json()
        if job['status'] in {'completed','failed'}:break
        time.sleep(.5)
    name='easyio_gpu_web_smoke' if args.easyio else 'local_web_smoke'
    (ROOT/f'results/{name}.json').write_text(json.dumps(job,indent=2,ensure_ascii=False),encoding='utf-8')
    assert job['status']=='completed',job
    result=job['result']
    assert result['model_version']=='identification-agents-v2'
    assert result['summary']['errors']==0
    if args.easyio:
        assert result['summary']['advisory_linked']==5
        assert result['summary']['unique_cves']==2
        assert result['summary']['candidate_records']==10
    else:assert result['summary']['validated']==1,result['components']
    assert result['summary']['candidate_records']>0
    assert result['summary']['matched_records']==0  # Flattened snapshot is not full applicability proof.
    assert all(result['components'][0][stage]['agent'] for stage in ('l2','l3','l4'))
    print('Real v2 GPU web handlers passed:',json.dumps(result['summary']),flush=True)


if __name__=='__main__':main()
