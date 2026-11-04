"""Run one supplied BOM through the running local service and retain its trace.

No source/asset facts are fabricated. The input vulnerability list is stripped
before identification, then compared only after the independent lookup finishes.
"""

from sbom_paths import public_sbom_file
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time
import requests

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.training_io import atomic_json


def main():
    source=public_sbom_file('icsa-26-281-03_SBOM-CVE.json')
    directory=ROOT/'results/simulations/icsa-26-281-03'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    directory.mkdir(parents=True)
    original=json.loads(source.read_text(encoding='utf-8'))
    reference=sorted({v['id'] for v in original.get('vulnerabilities',[])})
    supplied=json.loads(json.dumps(original));supplied.pop('vulnerabilities',None)
    state={'status':'running','input_file':str(source),'input_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
           'input_vulnerabilities_removed_before_identification':True,'supplied_source':False,'supplied_operational_asset_facts':{},
           'lookup_mode':'local','agent_mode':'tuned','started_at':datetime.now(timezone.utc).isoformat()}
    def save(phase):state['phase']=phase;atomic_json(directory/'status.json',state);print(phase,flush=True)
    api='http://127.0.0.1:8100';session=requests.Session()
    save('submitting_identification')
    response=session.post(api+'/api/cve-match/jobs',json={'sbom':supplied,'agent_mode':'tuned','lookup_mode':'local'},timeout=20)
    response.raise_for_status();job_id=response.json()['id'];state['job_id']=job_id
    last=None;deadline=time.monotonic()+900
    while time.monotonic()<deadline:
        r=session.get(api+'/api/cve-match/jobs/'+job_id,timeout=20);r.raise_for_status();job=r.json()
        progress=json.dumps(job.get('progress',{}),sort_keys=True)
        if progress!=last:save('identification: '+progress);last=progress
        if job['status']=='failed':raise RuntimeError(job.get('error'))
        if job['status']=='completed':break
        time.sleep(2)
    else:raise TimeoutError('Identification did not finish in the allotted observation window')
    atomic_json(directory/'identification.json',job)
    r=session.get(api+'/api/cve-match/jobs/'+job_id+'/vex',timeout=30);r.raise_for_status();handoff=r.json()
    atomic_json(directory/'handoff.json',handoff)
    found=sorted({c['cve'] for c in handoff['cves']})
    state['identified_cves']=found;state['reference_only_input_cves']=reference
    state['reference_comparison']={'recovered':sorted(set(found)&set(reference)),
        'not_recovered':sorted(set(reference)-set(found)),'additional_candidates':sorted(set(found)-set(reference))}
    save('shared_extraction_context_and_vex_authoring')
    # Empty asset means unknown environment, never a fictional safe deployment.
    r=session.post(api+'/api/cve-match/jobs/'+job_id+'/oc',json={'asset':{}},timeout=900);r.raise_for_status()
    vex=r.json();atomic_json(directory/'vex_result.json',vex)
    state.update(status='complete',completed_at=datetime.now(timezone.utc).isoformat(),vex_by_status=vex['by_status'],
                 pipeline=vex.get('pipeline'))
    save('complete');atomic_json(ROOT/'results/simulations/icsa-26-281-03/latest.json',{'directory':str(directory),**state})
    print(json.dumps({'directory':str(directory),'identified':found,'VEX':vex['by_status'],'pipeline':vex.get('pipeline')},indent=2),flush=True)


if __name__=='__main__':main()
