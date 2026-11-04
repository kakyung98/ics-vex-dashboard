from copy import deepcopy
import pytest
from fastapi.testclient import TestClient
from src.api_server import app,make_page
from src import operational_questions as OQ,vex_roles as VR
from tests.test_shared_vex_pipeline import provider,DESCRIPTION


def fake(monkeypatch,*,bad_quote=False,bad_ref=False):
    calls=[];original=provider(calls)
    def infer(role,packet):
        if role=='operation-questions':
            return {'prediction':{'questions':[{'question':q,'purpose':'Review frame processing.',
                'evidence':'invented' if bad_quote else 'malformed frames'} for q in
                ['On this asset, are frames processed?','On this asset, can an external sender supply frames?','On this asset, is frame parsing enabled?']]}}
        if role=='operation-assessment':
            return {'prediction':{'assessment':'likely_not_affected','explanation':'Operator reports the feature is not used; verification is needed.',
                'answer_refs':['foreign-question'] if bad_ref else [packet['questions_and_answers'][0]['id']],
                'missing_evidence':['Independent verification']}}
        return original(role,packet)
    monkeypatch.setattr(VR,'infer',infer)


def create():
    r=TestClient(app).post('/api/oc/questions',json={'product':'test-asset','simulation':True,
        'cves':[{'cve':'CVE-2099-12345','description':DESCRIPTION,'version_decided':False}]})
    assert r.status_code==200,r.text
    return r.json()


def test_questions_answers_and_writer_are_bound_to_same_case(monkeypatch):
    fake(monkeypatch);plan=create();row=plan['cases'][0]
    assert len(row['questions'])==4 and row['generation']['status']=='validated'
    assert {q['origin'] for q in row['questions']}=={'system','rule'}
    q=next(q for q in row['questions'] if q['answer_type']=='yes_no_unknown')
    result=TestClient(app).post('/api/oc/answers',json={'plan_id':plan['id'],
        'answers':{q['id']:{'value':'no','evidence':'Configuration inspection 2026-11-01'}}}).json()
    s=result['statements'][0]
    assert s['case_id']==row['case_id']
    assert s['operational_assessment']=='likely_cannot_determine'
    assert s['operational_review']['assessment']['llm_used'] is False
    assert s['operational_review']['assessment']['method']=='deterministic_answer_summary'
    assert s['status']==s['document_draft']['status']=='under_investigation'
    assert s['operational_review']['questions_and_answers'][1]['answer']['value']=='unknown'
    assert any(e['id']==q['id'] and 'Configuration inspection' in e['text'] for e in s['evidence_packet']['evidence'])
    assert 'confirmed installed product/version applicability' in s['evidence_packet']['missing_evidence']
    # The API retained a deep copy, not the client-modified question.
    row['questions'][0]['question']='fake question'
    assert 'fake question' not in str(s)


@pytest.mark.parametrize('bad_quote,bad_ref',[(True,False),(False,True)])
def test_failed_grounding_or_foreign_answer_ref_cannot_produce_likelihood(monkeypatch,bad_quote,bad_ref):
    fake(monkeypatch,bad_quote=bad_quote,bad_ref=bad_ref);plan=create()
    answers={q['id']:{'value':'yes','evidence':'operator record'} for q in plan['cases'][0]['questions']}
    r=OQ.assess(plan['id'],answers)['statements'][0]
    assert r['operational_assessment']=='likely_cannot_determine'
    assert r['status']=='under_investigation'


def test_missing_answers_or_no_records_stay_unknown(monkeypatch):
    fake(monkeypatch);plan=create()
    for answers in [{},{plan['cases'][0]['questions'][0]['id']:{'value':'no'}}]:
        s=OQ.assess(plan['id'],answers)['statements'][0]
        assert s['operational_assessment']=='likely_cannot_determine'


def test_answer_ids_are_not_reusable_on_another_plan(monkeypatch):
    fake(monkeypatch);a=create();b=create()
    with pytest.raises(ValueError):OQ.assess(b['id'],{a['cases'][0]['questions'][0]['id']:{'value':'no'}})
    with pytest.raises(ValueError):OQ.assess(a['id'],{a['cases'][0]['questions'][0]['id']:{'value':'no','status':'fixed'}})
    with pytest.raises(KeyError):OQ.assess('missing',{})


def test_expired_plan_and_invalid_answer_are_rejected(monkeypatch):
    fake(monkeypatch);plan=create();qid=plan['cases'][0]['questions'][-1]['id']
    with pytest.raises(ValueError):OQ.assess(plan['id'],{qid:{'value':'fixed'}})
    OQ._plans[plan['id']]['created_at']=0
    with pytest.raises(KeyError):OQ.assess(plan['id'],{})


def test_ui_uses_question_plan_before_answers():
    page=make_page('analyzer')
    assert '/api/item4/start' in page and '/questions' in page and '/answers' in page
    assert 'Required source missing' in page and 'common' in page
    assert 'Unknown / not answered' in page
