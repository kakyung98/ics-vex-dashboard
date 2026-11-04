import io,json,zipfile
from copy import deepcopy
import pytest
from fastapi.testclient import TestClient
from src import vex_roles as VR
from src.api_server import app,make_page

DESCRIPTION='The parse_frame function processes malformed frames.'


def provider(calls,*,bad_quote=False,bad_decision=False):
    def run(role,packet):
        calls.append((role,deepcopy(packet)))
        if role=='cve-conditions':
            pred={'conditions':[{'kind':'input','evidence':'invented payload' if bad_quote else 'malformed frames'}],
                  'function_candidates':[{'name':'parse_frame','evidence':'parse_frame function'}],
                  'function_status':'mentioned','assessment':'partial','can_refute':False}
        else:
            pred={'vulnerability':packet['vulnerability'],'product':packet['product'],
                  'status':'fixed' if bad_decision else packet['decision']['status'],
                  'justification':packet['decision']['justification'],
                  'impact_statement':('Simulated scenario. ' if packet['simulation'] else '')+packet['evidence'][0]['text'],
                  'evidence_refs':[e['id'] for e in packet['evidence']],'action_statement':None}
        return {'prediction':pred,'raw':json.dumps(pred),'role':role,'model':'test-fixture-only'}
    return run


@pytest.mark.parametrize('branch',['source','context'])
def test_both_branches_use_extractor_and_writer_with_same_case_packet(monkeypatch,branch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls));client=TestClient(app)
    cve={'cve':'CVE-2099-12345','description':DESCRIPTION,'functions':['parse_frame']}
    if branch=='source':
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:
            z.writestr('main.c','int parse_frame(int n){return n;} int main(void){return parse_frame(3);}\n')
            z.writestr('compile_commands.json',json.dumps([{'file':'main.c','arguments':['cc','-c','main.c']}]))
        up=client.post('/api/source/upload',files={'file':('source.zip',archive.getvalue(),'application/zip')})
        response=client.post('/api/source/judge',json={'session':up.json()['session'],'cves':[cve],
            'product':'fixture-product','analysis_scope':'product','entry_points':['main'],'tree_is_complete':True,'simulation':True})
    else:
        response=client.post('/api/oc/judge',json={'cves':[cve],'product':'fixture-product','asset':{},'simulation':True})
    assert response.status_code==200,response.text
    result=response.json();s=result['statements'][0]
    assert [c[0] for c in calls]==['vex-writer']
    assert s['extraction']['status']=='validated' and s['authoring']['status']=='validated_draft'
    assert s['pipeline_complete'] and result['pipeline']['answer_key_used'] is False
    assert s['document_draft']['status']==s['status']==s['evidence_packet']['decision']['status']
    assert s['case_id'] in s['document_draft']['evidence_refs'][0]
    assert 'tix' not in result and 'VEXGen' not in str(result)
    assert s['review_required'] is True


def test_analysis_ignores_model_quotation_provider(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls,bad_quote=True))
    cases=VR.prepare([{'cve':'CVE-2099-12345','description':DESCRIPTION}])
    assert not calls and cases[0]['extraction']['llm_used'] is False
    assert cases[0]['condition_function_candidates']==['parse_frame']
    assert all(c['evidence'] in DESCRIPTION for c in cases[0]['condition_candidates'])


def test_writer_cannot_change_locked_decision_or_export_rejected_draft(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls,bad_decision=True))
    result=TestClient(app).post('/api/oc/judge',json={'cves':[{'cve':'CVE-2099-12345','description':DESCRIPTION}]}).json()
    s=result['statements'][0]
    assert s['status']=='under_investigation' and s['authoring']['status']=='rejected'
    assert s['document_draft'] is None and result['vex_drafts']==[]
    assert len(s['authoring']['attempts'])==2
    assert [role for role,_ in calls].count('vex-writer')==2


def test_rule_extraction_keeps_case_identity_without_model_calls(monkeypatch):
    calls=[];monkeypatch.setattr(VR,'infer',provider(calls))
    a=VR.prepare([{'cve':'CVE-2099-12345','description':DESCRIPTION}],run_id='a')
    b=VR.prepare([{'cve':'CVE-2099-12345','description':DESCRIPTION}],run_id='b')
    assert not calls and a[0]['extraction']['prediction']==b[0]['extraction']['prediction']
    assert a[0]['case_id']!=b[0]['case_id']


def test_page_has_common_generation_and_no_paper_intermediate_output():
    for page in ['analyzer','vex-decision']:
        html=make_page(page)
        assert 'TIX' not in html and 'VEXGen' not in html and 'downloadSourceTix' not in html
    assert 'Generated VEX explanation (draft)' in make_page('analyzer')
