"""Exercise the real HTTP workflow with an explicitly fictional, source-poor BOM.

Use an isolated backend/database. This verifies conservative handling and VEX
serialization; it does not measure LLM accuracy or successful exploitation.
"""
import argparse
import json
import time
import uuid
from urllib.request import Request, urlopen


def run(base):
    def call(path,value=None):
        request=Request(base.rstrip('/')+path,
            data=None if value is None else json.dumps(value).encode(),
            headers={'Content-Type':'application/json'})
        with urlopen(request,timeout=60) as response:
            return json.loads(response.read())
    prefix='/api/item4/analyses'
    assert call('/api/health')['ok']
    catalogue=call(prefix+'/asset-keys')
    assert catalogue['question_count']==505
    document=dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
        metadata=dict(component={'bom-ref':'fictional-asset','type':'device',
            'name':'Fictional Operational VEX HTTP Smoke Asset','version':'1.0'}),
        vulnerabilities=[dict(id='CVE-2099-9999999',affects=[dict(ref='fictional-asset')])])
    submitted=call(prefix+'/start',dict(bom=document,request_id=uuid.uuid4().hex))
    path=prefix+'/jobs/'+submitted['id']
    deadline=time.monotonic()+45
    while True:
        job=call(path)
        if job['status'] in {'completed','failed'}:break
        if time.monotonic()>deadline:raise TimeoutError('Source analysis did not finish')
        time.sleep(.25)
    assert job['status']=='completed',job.get('error')
    assert job['conditions'][0]['status']=='unresolved'
    def token(job):return dict(revision=job['revision'],plan_sha256=job['plan_sha256'])
    job=call(path+'/answers',dict(token(job),answers={},context_answers={'mode':'normal'}))
    job=call(path+'/assess',token(job))
    assert job['assessment_state']=='completed'
    assert {r['product_vex_status'] for r in job['assessment']['decisions']}=={'under_investigation'}
    exports={kind:call(path+'/export/'+kind) for kind in ('analysis','review','openvex','cyclonedx')}
    assert exports['openvex']['statements'][0]['status']=='under_investigation'
    assert exports['cyclonedx']['bomFormat']=='CycloneDX'
    retry=call(path+'/retry',token(job))
    assert retry['id']==job['id'] and retry['assessment'] is None
    return dict(base=base,job_id=job['id'],catalogue_fields=505,
        source_status='unresolved',vex_status='under_investigation',
        export_formats=list(exports),retry_same_job=True,
        scope='Fictional source-poor input; real HTTP, persistence and serializers; no inference accuracy claim')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',default='http://127.0.0.1:18134')
    args=parser.parse_args()
    print(json.dumps(run(args.base),ensure_ascii=False,indent=2))
