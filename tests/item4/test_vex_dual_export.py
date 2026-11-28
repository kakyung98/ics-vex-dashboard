"""Exercise the public asset-input workflow with fixed source and graph fixtures."""
from copy import deepcopy
import json
import time

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
import pytest

from src.item4.workflow import source_analysis_jobs as Q; from src.item4.decision import asset_vex_assessment as E
from src.item4.analysis import asset_operating_question_generation as V3
from tests.item4.test_item4_asset_key_workflow import fixture_job, graph_fixture
from tools.item4 import serve_nist_operational_vex as service


CVE = 'CVE-2099-12345'
API = '/api/item4/analyses'
ADAPTER = dict(role='exploitation-prerequisites', sha256='b'*64, training_completed=True,
               evaluation_passed=False, evaluation_gate_override='explicit_user_request',
               experimental_use_approved=True, evaluation_sha256='c'*64)


@pytest.fixture
def workflow(tmp_path, monkeypatch):
    fixture, packet = fixture_job()
    artifact = fixture['conditions'][0]['prerequisite']
    artifact['model'] = {'adapter': ADAPTER}
    artifact['sha256'] = Q.vep.digest({k:v for k,v in artifact.items() if k != 'sha256'})
    monkeypatch.setattr(Q.store, 'DB', tmp_path / 'jobs.sqlite3')
    monkeypatch.setattr(Q, 'JOBS', {})
    monkeypatch.setattr(Q, 'extraction_identity', lambda: 'fixture')
    monkeypatch.setattr(Q, 'classify', lambda *_: deepcopy(fixture['asset_classification']))
    monkeypatch.setattr(Q, 'extract_declared', lambda *_, **kw: deepcopy(fixture['conditions'][0]))
    monkeypatch.setattr(Q, 'description_packet', lambda _: packet)
    monkeypatch.setattr(E.G, 'build', graph_fixture)
    # Export integration uses deterministic V3 responses, never a GPU model.
    real_question_job=V3.run_job
    def question_fixture(system,payload,**kwargs):
        return dict(llm_used=True,model={'model':'export-fixture'},prediction=dict(questions={
            key:dict(positive_fact=atom['positive_fact'],
                question='For this asset, is the following true: '+atom['positive_fact'].rstrip('.?!')+'?',
                check=atom['observation']['check'],record_type=atom['observation']['record_type'],confidence=95)
            for key,atom in payload['atoms'].items()}))
    monkeypatch.setattr(V3,'run_job',lambda job,progress=None,**kwargs:real_question_job(job,progress=progress,runner=question_fixture))

    def assess(bom=None, supplied_status='vulnerable', answer='o'):
        def version_binding(*_):
            return dict(state=supplied_status, product_bound=True,
                        condition_product_bound=supplied_status == 'vulnerable', sources=[])
        monkeypatch.setattr(E, 'version_binding', version_binding)
        client = TestClient(service.app)
        response = client.post(API + '/start', json={'bom': bom or fixture['input_bom']})
        assert response.status_code == 200, response.text
        url = API + '/jobs/' + response.json()['id']
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = client.get(url).json()
            if job['status'] in ('failed', 'completed'):
                break
            time.sleep(.02)
        assert job['status'] == 'completed', job.get('error',job)
        answers = {q['id']: answer for q in job['questions']}
        context = dict(scope='current_single', mode='normal')
        for case in job['assessment_cases']:
            context[case['prefix'] + 'deployment'] = 'running'
            context[case['prefix'] + 'runtime'] = 'bom'
        def token(state):
            return dict(revision=state['revision'], plan_sha256=state['plan_sha256'])
        saved = client.post(url + '/answers', json=dict(token(job), answers=answers, context_answers=context))
        assert saved.status_code == 200, saved.text
        assessed = client.post(url + '/assess', json=token(saved.json()))
        assert assessed.status_code == 200, assessed.text

        def download(kind):
            result = client.get(url + '/export/' + kind)
            assert result.status_code == 200, result.text
            assert 'attachment' in result.headers['content-disposition']
            return result.json()
        return download
    return assess


@pytest.mark.parametrize('version_state, answer, expected, cdx_state', [
    ('vulnerable', 'o', 'affected', 'exploitable'),
    ('vulnerable', 'unknown', 'under_investigation', 'in_triage'),
    ('unaffected', 'unknown', 'not_affected', 'not_affected'),
    ('fixed', 'unknown', 'fixed', 'resolved'),
])
def test_both_exports_agree_with_the_review(workflow, version_state, answer, expected, cdx_state):
    download = workflow(supplied_status=version_state, answer=answer)
    [row] = download('review')['decisions']
    [statement] = download('openvex')['statements']
    [entry] = download('cyclonedx')['vulnerabilities']
    assert row['status'] == statement['status'] == expected
    assert entry['analysis'] == dict(state=cdx_state, detail=row['reason'])
    assert statement['vulnerability']['name'] == entry['id'] == CVE
    notes = json.loads(statement['status_notes'])
    assert notes['component_ref'] == 'asset'
    decision = next(p for p in entry['properties'] if p['name'] == 'ics-vex:component-decision')
    assert notes['extraction_adapter'] == json.loads(decision['value'])['extraction_adapter']
    assert row['extraction_adapter'] == notes['extraction_adapter'] == ADAPTER
    assert entry['affects'] == [dict(ref='asset')]


def test_round_trip_preserves_original_vulnerabilities_and_relationships(workflow):
    versioned = {'bom-ref':'scanner-range','id':CVE,'source':{'name':'Scanner range'},
                 'affects':[{'ref':'asset','versions':[{'version':'1.0','status':'affected'}]},
                            {'ref':'library'}]}
    exact = {'bom-ref':'scanner-one','id':CVE,'detail':'Original description',
             'analysis':{'state':'in_triage','detail':'Initial review'},
             'affects':[{'ref':'asset'}]}
    other_issuer = {'bom-ref':'scanner-two','id':CVE, 'source':{'name':'Second issuer'},
                    'affects':[{'ref':'asset'}]}
    foreign = {'bom-ref':'ghsa','id':'GHSA-example','affects':[{'ref':'service'}],
               'recommendation':'Follow vendor instructions'}
    bom = dict(bomFormat='CycloneDX',specVersion='1.6',version=1,
               metadata={'component':{'bom-ref':'asset','name':'Fixture HMI','type':'device','version':'1.0'}},
               components=[{'bom-ref':'library','type':'library','name':'Library','version':'2.0'}],
               services=[{'bom-ref':'service','name':'Telemetry'}],
               compositions=[{'aggregate':'complete','vulnerabilities':['scanner-one','scanner-two','scanner-range','ghsa']}],
               vulnerabilities=[foreign,versioned,exact,other_issuer])
    download = workflow(bom)
    output = download('cyclonedx')
    rows = {v['bom-ref']: v for v in output['vulnerabilities']}
    assert rows['ghsa'] == foreign
    assert rows['scanner-range'] == versioned
    for ref in ('scanner-one','scanner-two'):
        assert rows[ref]['analysis']['state'] == 'exploitable'
        assert rows[ref]['affects'] == [{'ref':'asset'}]
    assert rows['scanner-one']['detail'] == exact['detail']
    prior = next(p['value'] for p in rows['scanner-one']['properties'] if p['name']=='ics-vex:prior-analysis')
    assert json.loads(prior) == exact['analysis']
    assert rows['scanner-two']['source'] == other_issuer['source']
    assert len(rows) == len(output['vulnerabilities']) == 4
    assert not any(entry.get('affects')==[{'ref':'library'}] and 'properties' in entry
                   for entry in output['vulnerabilities']), 'Unselected components must not receive new VEX decisions'
    assert output['compositions'] == bom['compositions']
    assert download('analysis')['input_bom'] == bom


def test_spdx_projection_retains_package_refs_and_dependency(workflow):
    ref = 'SPDXRef-library'
    bom = dict(spdxVersion='SPDX-2.3',name='Fixture',SPDXID='SPDXRef-DOCUMENT',
               documentNamespace='https://example.invalid/document',documentDescribes=[ref],
               packages=[dict(SPDXID=ref,name='Library',versionInfo='1.0',primaryPackagePurpose='LIBRARY',
                              externalRefs=[dict(referenceType='purl',referenceLocator='pkg:generic/library@1.0')]),
                         dict(SPDXID='SPDXRef-app',name='App',versionInfo='2.0')],
               relationships=[dict(spdxElementId='SPDXRef-app',relatedSpdxElement=ref,relationshipType='DEPENDS_ON')],
               vulnerabilities=[dict(id=CVE,affects=[dict(ref=ref)])])
    download = workflow(bom)
    exported = download('cyclonedx')
    components = {v['bom-ref']:v for v in exported['components']}
    assert components[ref]['type'] == 'library'
    assert components[ref]['purl'] == 'pkg:generic/library@1.0'
    assert dict(ref='SPDXRef-app',dependsOn=[ref]) in exported['dependencies']
    assert exported['vulnerabilities'][0]['affects'] == [dict(ref=ref)]
    assert download('analysis')['input_bom'] == bom


def test_download_controls_and_retired_routes():
    client = TestClient(service.app)
    response = client.get('/item4.html')
    assert response.status_code == 200
    page = BeautifulSoup(response.text,'html.parser')
    assert 'OpenVEX' in page.select_one('#download-openvex').text
    assert 'CycloneDX' in page.select_one('#download-cyclonedx').text
    for path in ('/api/bom-vex/workflows/old/export/cyclonedx',
                 '/api/bom-vex/workflows/old/cases/old/export/openvex'):
        assert client.get(path).status_code == 410
