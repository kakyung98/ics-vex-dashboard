
from src.dataset_paths import public_sbom_file
import time
import json

from fastapi.testclient import TestClient
from src.api_server import app
from ics_agent_matcher_full.ics_agent_matcher.matcher import make_l4, NVD, CPE_API
from src.identification_tasks import identity_gold
from src.candidate_advisories import retrieve


client=TestClient(app)


def test_job_validation_and_unknown_job():
    assert client.post('/api/cve-match/jobs',json={'sbom':{}}).status_code==400
    assert client.post('/api/cve-match/jobs',json={'sbom':{'bomFormat':'CycloneDX','components':[]}}).status_code==400
    assert client.get('/api/cve-match/jobs/nonexistent').status_code==404


def test_model_metadata_and_navigation():
    data=client.get('/api/cve-match/models').json()
    assert len(data['tasks'])==3
    assert all('ready' in t for t in data['tasks'])
    root=client.get('/').text
    assert 'id="candidate-workspace"' in root
    assert 'id="candidate-vex"' in root
    assert 'side-brand' in root and 'SSRC' in root
    assert '/api/source/upload' in root
    assert '/api/item4/start' in root and '/questions' in root and '/answers' in root
    redirect=client.get('/cve-matcher.html',follow_redirects=False)
    assert redirect.status_code==307 and redirect.headers['location']=='/'
    page=client.get('/cve-matcher.html').text
    assert '/api/cve-match/jobs' in page
    assert 'Generalization to real SBOMs is unverified' in page


def test_local_snapshot_job_never_fabricates_complete_applicability(monkeypatch):
    monkeypatch.delenv('SLLM_BASE_URL',raising=False)
    response=client.post('/api/cve-match/jobs',json={
        'sbom':{'bomFormat':'CycloneDX','components':[{'name':'curl','version':'7.23.1'}]},
        'agent_mode':'rules','lookup_mode':'local'})
    assert response.status_code==202,response.text
    job_id=response.json()['id']
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        job=client.get('/api/cve-match/jobs/'+job_id).json()
        if job['status'] in {'completed','failed'}:break
        time.sleep(.05)
    assert job['status']=='completed',job
    result=job['result']
    assert result['summary']['validated']==1
    assert result['summary']['candidate_records']>0
    assert result['summary']['matched_records']==0
    assert all(v['match_status']=='unknown' for r in result['components'] for v in r['cves'])
    assert job['progress']['done']==1
    assert 'platform' in result['lookup_notice']


def test_l4_compacts_releases_without_hiding_a_competing_identity():
    records=[{'cpe':{'cpeName':f'cpe:2.3:a:haxx:curl:7.{i}:*:*:*:*:*:*:*'}} for i in range(228)]
    records.append({'cpe':{'cpeName':'cpe:2.3:a:another:curl:1.0:*:*:*:*:*:*:*'}})
    key=json.dumps([CPE_API,{'keywordSearch':'curl','resultsPerPage':100}],sort_keys=True)
    nvd=NVD(offline=True,fixtures={key:{'products':records}})
    received=[]
    def agents(task,payload):
        received.append(payload)
        return {'prediction':identity_gold(payload)}
    result=make_l4(nvd,agents)({'component':{'name':'curl'},'l2':{'normalized':'curl'}})['l4']
    assert len(received[0]['candidates'])==2
    assert result['agent']['dictionary_records']==229
    assert result['agent']['distinct_identities']==2
    assert result['candidates']==[]  # Two vendors remain ambiguous after compaction.


def test_easyio_real_upload_regression_does_not_read_input_vulnerability_answers():
    from pathlib import Path
    from src.candidate_match import match_candidates
    root=Path(__file__).resolve().parents[1]
    sbom=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8'))
    sbom['vulnerabilities']=[{'id':'CVE-1999-999999'}]
    result=match_candidates(sbom,agent_mode='rules',lookup_mode='local')
    assert result['summary']['advisory_linked']==5
    assert result['summary']['candidate_records']==10
    for row in result['components']:
        assert {v['cve_id'] for v in row['cves']}=={'CVE-2026-64892','CVE-2026-64893'}
        assert all(v['match_status']=='unknown' for v in row['cves'])
        assert all(v['evidence']['advisory_id'] for v in row['cves'])
    assert not retrieve({'name':'EasyIO Neo Series EC and CW Controllers','supplier':'Unrelated Vendor'})
    # A release label outside the affected phrase still permits family candidate
    # lookup; it must never become evidence that this release is affected/fixed.
    family=retrieve({'name':'Johnson Controls EasyIO Neo Series EC Controllers V3.3b64','supplier':'Johnson Controls'})
    assert family and all(r['match_status']=='unknown' and not r['evidence']['version_confirmed'] for r in family)


def test_unknown_version_still_retrieves_candidates_without_claiming_affected():
    from ics_agent_matcher_full.ics_agent_matcher.matcher import run,CVE_API
    observed=[]
    class Fixture(NVD):
        def get_all(self,path,params,field):
            if path==CPE_API:return {'products':[{'cpe':{'cpeName':'cpe:2.3:a:haxx:curl:7.23.1:*:*:*:*:*:*:*'}}]}
            observed.append(params)
            return {'vulnerabilities':[{'cve':{'id':'CVE-2020-0001','configurations':[{'nodes':[{'cpeMatch':[{'criteria':'cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*','vulnerable':True}]}]}]}}]}
    result=run({'bomFormat':'CycloneDX','components':[{'name':'curl','version':'NOASSERTION'}]},Fixture(offline=True))
    row=result['components'][0]
    assert row['validation']['status']=='validated'
    assert row['validation']['version_status']=='unknown'
    assert 'virtualMatchString' in observed[0]
    assert row['cves'][0]['match_status']=='unknown'
    assert row['execution']['l3']['executed'] is True
    assert row['execution']['l3']['reason']=='installed_version_unknown'
    assert row['execution']['l4']['executed'] is True


def test_integrated_candidate_handoff_and_context_do_not_upgrade_unknown_versions(monkeypatch):
    from pathlib import Path
    import src.api_server as server
    sbom=json.loads((public_sbom_file('icsa-26-274-04_SBOM-CVE.json')).read_text(encoding='utf-8'))
    sbom['vulnerabilities']=[{'id':'CVE-1999-999999'}]
    response=client.post('/api/cve-match/jobs',json={'sbom':sbom,'agent_mode':'rules','lookup_mode':'local'})
    job_id=response.json()['id'];deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        if client.get('/api/cve-match/jobs/'+job_id).json()['status']=='completed':break
        time.sleep(.05)
    response=client.get('/api/cve-match/jobs/'+job_id+'/vex')
    assert response.status_code==200,response.text
    data=response.json()
    assert {r['cve'] for r in data['cves']}=={'CVE-2026-64892','CVE-2026-64893'}
    assert data['mapping_count']==12  # Five components plus the separately reviewed representative asset.
    assert all(r['final_vex']=='UNDER_INVESTIGATION' and not r['version_decided'] for r in data['cves'])
    assert data['sbom']['metadata']['component']['name']==sbom['metadata']['component']['name']
    def satisfied(cases):
        return {'statements':[{'cve':c['cve'],'status':'affected','justification':None} for c in cases]}
    monkeypatch.setattr(server.OCJ,'judge_many',satisfied)
    result=client.post('/api/cve-match/jobs/'+job_id+'/oc',json={'asset':{}})
    assert result.status_code==200,result.text
    assert all(s['status']=='under_investigation' for s in result.json()['statements'])
    assert result.json()['decision_rate']==0


def test_integrated_document_has_unique_ids():
    from html.parser import HTMLParser
    class IDs(HTMLParser):
        def __init__(self):super().__init__();self.ids=[]
        def handle_starttag(self,tag,attrs):
            self.ids.extend(value for key,value in attrs if key=='id')
    parser=IDs();parser.feed(client.get('/').text)
    assert len(parser.ids)==len(set(parser.ids))
    assert 'cm-sbom' in parser.ids


def test_english_ui_and_current_method_remove_obsolete_navigation():
    import re
    from html.parser import HTMLParser
    class Visible(HTMLParser):
        def __init__(self):super().__init__();self.skip=0;self.text=[]
        def handle_starttag(self,tag,attrs):
            if tag in {'script','style'}:self.skip+=1
        def handle_endtag(self,tag):
            if tag in {'script','style'}:self.skip-=1
        def handle_data(self,data):
            if not self.skip:self.text.append(data)
    for url in ('/','/sbom-to-cve.html'):
        page=client.get(url).text;parser=Visible();parser.feed(page)
        assert not re.search('[가-힣]',' '.join(parser.text))
        assert '6W problems &amp;' not in page
        assert 'href="cve-matcher.html"' not in page
    method=client.get('/sbom-to-cve.html').text
    assert 'The nine limits' not in method
    assert 'Query NVD &amp; CISA' in method
    assert client.get('/context-vex.html',follow_redirects=False).status_code==307
    schema=client.get('/api/oc/fields').json()
    for group in schema['groups']:
        assert not re.search('[가-힣]',group['label'])
        for field in group['fields']:
            assert not re.search('[가-힣]',field['label']+field['help']+field['source'])
