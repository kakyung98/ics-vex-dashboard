"""Behavioral regression tests for the operational-context redesign."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.operational_workflow_api import router
from src.question_mining_api import router as review_router
from src.cluster_question_pipeline import evaluate_plan
from src.context_vex_pipeline import logic


@pytest.fixture
def client():
    app=FastAPI();app.include_router(router);app.include_router(review_router)
    return TestClient(app)


def source_review(client,cve,extra=False):
    text='Successful exploitation requires web management enabled and network access'+(' and administrator privileges' if extra else '')+'.'
    response=client.post('/api/operational-workflow/source',json=dict(cve=cve,source='synthetic fixture',text=text))
    assert response.status_code==200,response.text
    source=response.json()
    phrases=['web management enabled','network access']+(['administrator privileges'] if extra else [])
    predicates=['feature_enabled','network_reachable','attacker_has_required_privilege']
    conditions=[]
    for i,quote in enumerate(phrases):
        start=text.index(quote)
        conditions.append(dict(id='c'+str(i),predicate=predicates[i],target='web management interface',
            value='administrator' if i==2 else '',explicitness='explicit',
            source_refs=[dict(source_id='advisory',quote=quote,span=[start,start+len(quote)])]))
    return dict(source_id=source['source_id'],conditions=conditions,
        formula=dict(op='and',args=[dict(condition=c['id']) for c in conditions]),coverage_complete=False)


def compiled(client,threshold=.8):
    reviews=[source_review(client,'DEMO-'+str(i),i==3) for i in (1,2,3)]
    response=client.post('/api/operational-workflow/compile',json=dict(reviews=reviews,reviewer='Test reviewer',review_confirmed=True,k=1,threshold=threshold))
    assert response.status_code==200,response.text
    return response.json()


def test_common_support_preserves_rare_condition_and_domains(client):
    w=compiled(client)
    assert w['clustering']['selected_k']==1
    assert len(w['plan']['common_questions'])==2
    rare=next(t for t in w['template_catalog'] if t['predicate'].startswith('attacker_has_required_privilege'))
    assert rare['support']==pytest.approx(1/3)
    assert not rare['common'] and rare['domain']=='O3'
    assert 'administrator' in rare['text']
    c=next(c for c in w['plan']['cves'] if c['cve']=='DEMO-3')
    assert not c['specific_questions']
    assert len(c['unresolved_condition_ids'])==1  # Operator roles cannot prove attacker possession.


def test_raising_support_threshold_demotes_without_losing_questions(client):
    reviews=[source_review(client,'DEMO-'+str(i),i>1) for i in (1,2,3)]
    # This test concerns observable access-rule configuration, not attacker credentials.
    for row in reviews:
        for c in row['conditions']:
            if c['predicate']=='attacker_has_required_privilege':c['predicate']='privilege_required'
    def run(t):
        r=client.post('/api/operational-workflow/compile',json=dict(reviews=reviews,reviewer='R',review_confirmed=True,k=1,threshold=t))
        assert r.status_code==200,r.text
        return r.json()['plan']
    low,high=run(.6),run(.8)
    assert len(low['common_questions'])==3 and len(high['common_questions'])==2
    assert sum(len(c['specific_questions']) for c in high['cves'])==2


def test_tampered_source_and_missing_review_rejected(client):
    row=source_review(client,'DEMO-1')
    body=dict(reviews=[row],reviewer='R',review_confirmed=False,k=1)
    assert client.post('/api/operational-workflow/compile',json=body).status_code==422
    body['review_confirmed']=True
    row['conditions'][0]['source_refs'][0]['quote']='invented quotation'
    assert client.post('/api/operational-workflow/compile',json=body).status_code==422


def test_or_not_unknown_are_not_flattened(client):
    row=source_review(client,'DEMO-1')
    row['formula']={'op':'or','args':[{'condition':'c0'},{'op':'not','args':[{'condition':'c1'}]}]}
    r=client.post('/api/operational-workflow/compile',json=dict(reviews=[row],reviewer='R',review_confirmed=True,k=1))
    assert r.status_code==200,r.text
    formula=r.json()['plan']['reviews'][0]['formula']['expression']
    assert formula==row['formula']
    assert logic(formula,{'c0':'false','c1':'unknown'})=='unknown'
    assert logic(formula,{'c0':'false','c1':'false'})=='true'


def test_answers_persist_export_and_do_not_promote_network_observations(client):
    w=compiled(client)
    now=datetime.now(timezone.utc)
    body=dict(scope=dict(asset_ref='PLC-1',product='Example PLC',build='1',config_baseline='baseline-A',mode='normal | actor: vendor'),
        observed_at=(now-timedelta(minutes=1)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat(),
        answers=[dict(question_id=q['id'],value='no',source='ACL-1',quote='Network access denied',kind='firewall_policy') for q in w['plan']['common_questions']])
    response=client.post('/api/question-mining/reviews/'+w['id']+'/answers',json=body)
    assert response.status_code==200,response.text
    result=response.json()
    assert all(d['status']=='under_investigation' for d in result['decisions'])
    assert all(d['formula_value']=='false' for d in result['decisions'])
    assert 'openvex' in result and 'csaf_vex' in result
    resumed=client.get('/api/question-mining/reviews/'+w['id']).json()
    assert resumed['last_evaluation']==result


def test_draft_restore_hash_check_and_unique_questions(client):
    text='Network access is required.'
    record=dict(cve='DEMO-1',sources=[dict(id='s',text=text,text_sha256=hashlib.sha256(text.encode()).hexdigest())])
    assert client.post('/api/operational-workflow/restore-source',json={'record':record}).status_code==200
    record['sources'][0]['text']='tampered'
    assert client.post('/api/operational-workflow/restore-source',json={'record':record}).status_code==422
    w=compiled(client)
    ids=[q['id'] for r in w['plan']['reviews'] for q in r['questions']]
    assert len(ids)==len(set(ids))


def test_invalid_k_and_threshold_and_unmapped_retention(client):
    row=source_review(client,'DEMO-1')
    body=dict(reviews=[row],reviewer='R',review_confirmed=True,k=1)
    for key,val in [('k',5),('threshold',0),('threshold',1.1),('min_support',1)]:
        assert client.post('/api/operational-workflow/compile',json={**body,key:val}).status_code==422
    row['conditions'][0].update(predicate='custom',value='reviewed custom prerequisite')
    r=client.post('/api/operational-workflow/compile',json=body)
    assert r.status_code==200,r.text
    assert any(t['domain']=='unmapped' for t in r.json()['template_catalog'])


def test_english_unified_page():
    from src.operational_workflow_page import render
    import re
    html=render()
    assert '<html lang="en">' in html
    from bs4 import BeautifulSoup
    document=BeautifulSoup(html,'html.parser')
    for node in document(['script','style']):node.decompose()
    assert not re.search('[\uac00-\ud7af]',document.get_text())
    assert 'ics-workspace-theme' in html and 'class="side"' in html
    assert '/* WORKFLOW_SCRIPT */' not in html
    assert 'Cluster & build question plan' in html
