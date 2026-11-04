
from src.dataset_paths import public_sbom_file
import json,time
from copy import deepcopy
from pathlib import Path
from fastapi.testclient import TestClient
from src.unified_identification import run_unified
from src.identity_retrieval import ProductIndex
from src.identification_tasks import version_gold,identity_gold
from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD,norm
from tests.test_identity_evidence import index,sbom


def provider(calls,proposal=None,wrong_version=False,pick_vendor=None):
    def infer(task,packet):
        calls.append((task,deepcopy(packet)))
        if task=='L2':
            eligible=[c['candidate_id'] for c in packet['candidates'] if not c['conflicts']]
            p={'ranked_candidate_ids':eligible,'evidence_refs':['input:name'] if eligible else [],'status':'ranked' if eligible else 'unresolved'}
        elif task=='L3':
            p=version_gold(packet['raw_version'])
            if wrong_version:p={'normalized':'1.2.3','status':'present'}
        else:
            p=identity_gold(packet)
            if pick_vendor:p={'vendor':pick_vendor,'product':packet['normalized_name'],'status':'validated'}
        return {'prediction':p,'raw':json.dumps(p),'mode':'tuned'}
    return infer



def test_identification_never_calls_injected_model_or_ranker():
    calls=[]
    def forbidden(*args):calls.append(args);raise AssertionError('No analysis model allowed')
    r=run_unified(sbom(),NVD(offline=True),index=index(),agents=forbidden,ranker=forbidden)
    assert not calls and r['llm_used'] is False
    assert r['components'][0]['validation']['product']=='curl'

def test_revision_and_purl_versions_are_preserved_without_a_model():
    for data in [sbom(version='v1.2.3-vendor4'),sbom(version='NOASSERTION',purl='pkg:generic/curl@1.2.3-vendor4')]:
        row=run_unified(data,NVD(offline=True),index=index())['components'][0]
        assert row['l3']['normalized']=='1.2.3-vendor4'
    data['properties']=[{'name':'dataset:synthetic-inventory','value':'true'}]
    assert run_unified(data,NVD(offline=True),index=index())['components'][0]['l3']['normalized'] is None

def test_ambiguity_not_resolved_by_supplier_and_competitors_retained():
    idx=ProductIndex([{'cpe':f'cpe:2.3:a:v{i}:controller:1.0:*:*:*:*:*:*:*'} for i in range(15)])
    row=run_unified(sbom(name='controller',supplier='v0'),NVD(offline=True),index=idx)['components'][0]
    assert row['validation']['status']=='unresolved' and len(row['l2']['candidates'])==15

def test_default_api_is_model_free_and_handoff_keeps_provenance(monkeypatch):
    from src.api_server import app
    from src import identification_agents as runtime
    monkeypatch.setattr(runtime,'get_runtime',lambda: (_ for _ in ()).throw(AssertionError('GPU must not load')))
    data=json.loads(public_sbom_file('icsa-26-274-04_SBOM-CVE.json').read_text(encoding='utf-8'))
    client=TestClient(app);jid=client.post('/api/cve-match/jobs',json={'sbom':data,'lookup_mode':'local'}).json()['id']
    for _ in range(400):
        job=client.get('/api/cve-match/jobs/'+jid).json()
        if job['status'] in {'completed','failed'}:break
        time.sleep(.05)
    assert job['status']=='completed',job
    assert job['result']['architecture']=='deterministic-identification-v1'
    assert job['result']['summary']['unique_cves']==2
    assert client.get('/api/cve-match/jobs/'+jid+'/vex').json()['mapping_count']==12
