"""Durable source review, scoped answer reuse and formal export integration."""
import pytest,hashlib
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src import question_mining_api as api,review_store
from src.question_pattern_mining import mine
from tests.test_cluster_question_pipeline import fixture


@pytest.fixture
def client(tmp_path,monkeypatch):
    _,records,_,_=fixture()
    for record in records:
        for source in record['sources']:source['text_sha256']=hashlib.sha256(source['text'].encode()).hexdigest()
    rows=[dict(cve=r['cve'],condition_id=r['cve']+':condition',condition='network access available',
               kind='access_position',necessity='explicitly_required',source_id=r['sources'][0]['id'],
               source_span=[0,len(r['sources'][0]['text'])],source_quote=r['sources'][0]['text']) for r in records]
    result=mine(rows,[r['cve'] for r in records],min_cves=2)
    store=dict(summary=result['summary'],cves={r['cve']:r for r in result['cves']},
               atoms={r['id']:r for r in result['atoms']},patterns=result['patterns'],records={r['cve']:r for r in records})
    monkeypatch.setattr(api,'data',lambda:store);monkeypatch.setattr(review_store,'DB',tmp_path/'sessions.sqlite3')
    app=FastAPI();app.include_router(api.router)
    return TestClient(app)


def create(client,cve,complete=False):
    detail=client.get('/api/question-mining/cves/'+cve).json()
    aid=detail['atoms'][0]['id'];cid=detail['atoms'][0]['sources'][0]['condition_id']
    response=client.post('/api/question-mining/reviews',json=dict(cve=cve,reviewer='explicit synthetic test reviewer',
        source_review_confirmed=True,conditions=[dict(condition_id=cid,predicate=aid,target='same-interface',
        question='Is this interface reachable?',yes_means='true')],formula={'condition':cid},coverage_complete=complete))
    assert response.status_code==200,response.text
    return response.json()


def test_two_reviews_merge_into_one_common_answer_and_scoped_csaf(client):
    a=create(client,'SIM-A');b=create(client,'SIM-B')
    merged=client.post('/api/question-mining/reviews/merge',json=dict(session_ids=[a['id'],b['id']],reviewer='synthetic reviewer')).json()
    assert len(merged['plan']['common_questions'])==1
    question=merged['plan']['common_questions'][0]
    payload=dict(scope=dict(asset_ref='asset',product='controller',build='1',config_baseline='test',mode='normal'),
        observed_at='2026-01-01T00:00:00Z',valid_until='2030-01-01T00:00:00Z',answers=[dict(question_id=question['id'],value='no',source='synthetic record',quote='Controlled fixture only')])
    response=client.post('/api/question-mining/reviews/'+merged['id']+'/answers',json=payload)
    assert response.status_code==200,response.text
    result=response.json()
    assert len(result['propagated_answers'])==2
    assert all(d['status']=='under_investigation' for d in result['decisions'])
    assert result['csaf_vex']['document']['category']=='csaf_vex'
    payload['product_assertion']=dict(status='affected',cves=['SIM-A'],source='synthetic supplier assertion',
        quote='Fixture product explicitly affected',action_statement='Apply the explicit fixture fix')
    response=client.post('/api/question-mining/reviews/'+merged['id']+'/answers',json=payload)
    assert response.status_code==200,response.text
    assert [d['status'] for d in response.json()['decisions']]==['affected','under_investigation']
    saved=review_store.get('pattern-workbench',merged['id'])
    assert len(saved['history'])==2


def test_missing_source_review_and_unknown_questions_are_rejected(client):
    assert client.post('/api/question-mining/reviews',json=dict(cve='SIM-A')).status_code==422
    saved=create(client,'SIM-A')
    assert client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=dict(scope={},answers=[
        dict(question_id='unknown',value='yes')])).status_code==422


def test_fixed_requires_installation_and_active_execution(client):
    saved=create(client,'SIM-A')
    payload=dict(scope=dict(asset_ref='asset',product='controller',build='1',config_baseline='test',mode='normal'),
        observed_at='2026-01-01T00:00:00Z',valid_until='2030-01-01T00:00:00Z',answers=[],product_assertion=dict(status='fixed',
        source='synthetic mapping',quote='Explicit fixture fix mapping'))
    url='/api/question-mining/reviews/'+saved['id']+'/answers'
    response=client.post(url,json=payload)
    assert response.status_code==200,response.text
    assert response.json()['decisions'][0]['status']=='under_investigation'
    payload['product_assertion']['installation']=dict(source='synthetic deployment record',quote='Fixture build running',execution_verified=True)
    response=client.post(url,json=payload)
    assert response.status_code==200,response.text
    assert response.json()['decisions'][0]['status']=='fixed'


@pytest.mark.parametrize('kind,complete,expected',[
    ('operational_observation',True,'under_investigation'),
    ('firewall_policy',True,'under_investigation'),
    ('reviewed_nonexecution_analysis',False,'under_investigation'),
    ('reviewed_nonexecution_analysis',True,'not_affected')])
def test_structural_refutation_requires_both_source_completeness_and_records(client,kind,complete,expected):
    saved=create(client,'SIM-A',complete)
    q=saved['plan']['cves'][0]['specific_questions'][0]
    payload=dict(scope=dict(asset_ref='asset',product='controller',build='1',config_baseline='test',mode='normal'),
        observed_at='2026-01-01T00:00:00Z',valid_until='2030-01-01T00:00:00Z',
        answers=[dict(question_id=q['id'],value='no',kind=kind,source='synthetic structural record',quote='Fixture condition structurally absent')],
        route_analyses={'SIM-A':dict(source='synthetic exhaustive route record',quote='All fixture alternatives reviewed',review_confirmed=True)})
    response=client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=payload)
    assert response.status_code==200,response.text
    assert response.json()['decisions'][0]['status']==expected
    reopened=client.get('/api/question-mining/reviews/'+saved['id']).json()
    assert reopened['last_evaluation']['decisions'][0]['status']==expected


def test_observation_times_are_not_fabricated_by_the_server(client):
    saved=create(client,'SIM-A');qid=saved['plan']['cves'][0]['specific_questions'][0]['id']
    response=client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=dict(
        scope=dict(asset_ref='asset',product='controller',build='1',config_baseline='test',mode='normal'),
        answers=[dict(question_id=qid,value='yes',source='synthetic',quote='test')]))
    assert response.status_code==422


def test_manual_special_question_requires_an_exact_source_quote(client):
    record=api.data()['records']['SIM-A'];source=record['sources'][0]
    payload=dict(cve='SIM-A',reviewer='synthetic test reviewer',source_review_confirmed=True,
        conditions=[dict(condition_id='manual:SIM-A:1',predicate='reviewed_fact',target='specific test target',
            question='Is the reviewed fixture fact true?',yes_means='true',
            source_ref=dict(source_id=source['id'],span=[0,len(source['text'])],quote=source['text']))],
        formula={'condition':'manual:SIM-A:1'},coverage_complete=False)
    response=client.post('/api/question-mining/reviews',json=payload)
    assert response.status_code==200,response.text
    assert response.json()['plan']['cves'][0]['specific_questions']
    payload['conditions'][0]['source_ref']['quote']='Invented source condition'
    assert client.post('/api/question-mining/reviews',json=payload).status_code==422


def test_catalogue_min_support_does_not_block_two_matching_reviewed_facts(client):
    store=api.data()
    for row in store['cves'].values():row['common_template_ids']=[]
    a=create(client,'SIM-A');b=create(client,'SIM-B')
    merged=client.post('/api/question-mining/reviews/merge',json=dict(session_ids=[a['id'],b['id']],reviewer='synthetic reviewer'))
    assert merged.status_code==200,merged.text
    assert len(merged.json()['plan']['common_questions'])==1


def test_inferred_relation_is_selected_on_server_and_retained_in_csaf(client):
    source=api.data()['records']['SIM-A']['sources'][0]
    source['text']='Successful exploitation requires network access and user interaction.'
    source['text_sha256']=hashlib.sha256(source['text'].encode()).hexdigest()
    value=client.get('/api/question-mining/cves/SIM-A/logic').json()
    p=value['passages'][0];h=p['hypotheses'][0]
    payload=dict(cve='SIM-A',reviewer='synthetic source reviewer',source_review_confirmed=True,
        conditions=[dict(condition_id=c['id'],target='specific simulated '+str(i),question=c['question'],yes_means='true') for i,c in enumerate(p['conditions'])],
        formula=h['expression'],inference_selection=dict(passage=0,hypothesis=0),coverage_complete=False)
    response=client.post('/api/question-mining/reviews',json=payload)
    assert response.status_code==200,response.text
    saved=response.json();formula=saved['plan']['reviews'][0]['formula']
    assert formula['expression']['op']=='and' and formula['inference']['inferred_before_user_review']
    answer=client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=dict(
        scope=dict(asset_ref='fixture',product='fixture',build='1',config_baseline='test',mode='normal'),answers=[]))
    assert answer.status_code==200,answer.text
    exported=answer.json()['csaf_vex']['vulnerabilities'][0]['analysis']['product_analyses'][0]['formula']
    assert exported['inference']['method'].startswith('source-clause-boolean-inference/')
    payload['formula']={**h['expression'],'op':'or'}
    assert client.post('/api/question-mining/reviews',json=payload).status_code==422


def test_ambiguous_inference_needs_explicit_attachment_choice(client):
    source=api.data()['records']['SIM-A']['sources'][0]
    source['text']='Successful exploitation requires A and B or C.'
    source['text_sha256']=hashlib.sha256(source['text'].encode()).hexdigest()
    value=client.get('/api/question-mining/cves/SIM-A/logic').json();p=value['passages'][0];h=p['hypotheses'][0]
    payload=dict(cve='SIM-A',reviewer='synthetic reviewer',source_review_confirmed=True,
        conditions=[dict(condition_id=c['id'],target='fixture '+str(i),question=c['question'],yes_means='true') for i,c in enumerate(p['conditions'])],
        formula=h['expression'],inference_selection=dict(passage=0,hypothesis=0))
    assert client.post('/api/question-mining/reviews',json=payload).status_code==422
    payload['inference_selection']['alternative']=0
    assert client.post('/api/question-mining/reviews',json=payload).status_code==200
