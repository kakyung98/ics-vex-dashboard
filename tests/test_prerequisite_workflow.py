"""Synthetic counterexamples for source-grounded path clustering and reuse."""
from copy import deepcopy
import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src import operational_workflow_api as api, review_store
from src.operational_workflow import build_workflow
from src.prerequisite_paths import attack_paths
from tests.test_cluster_question_pipeline import fixture


def population():
    reviews,records,_,_=fixture()
    for review in reviews:
        for condition in review['conditions']:condition['explicitness']='explicit'
    return reviews,records


def test_or_paths_do_not_promote_a_branch_condition_to_all_paths():
    reviews,records=population()
    result=build_workflow(reviews,records,k=1,threshold=.8)
    assert len(result['clustering']['paths'])==3
    network=next(t for t in result['template_catalog'] if t['predicate']=='network_reachable')
    assert network['support']==pytest.approx(2/3)
    assert network['unknown_paths']==1
    assert not network['common']
    assert not result['plan']['common_questions']
    assert all(c['specific_questions'] for c in result['plan']['cves'])
    assert result['plan']['reviews'][1]['formula']==reviews[1]['formula']


def test_same_cve_can_belong_to_several_path_clusters():
    reviews,records=population()
    result=build_workflow(reviews,records,k=2)
    b=next(m for m in result['clustering']['memberships'] if m['cve']=='SIM-B')
    assert len(b['cluster_ids'])==2
    assert result['support_policy']['denominator']=='attack paths in cluster'


def test_not_preserves_signed_literals_and_distributes_with_demorgan():
    expr={'op':'not','args':[{'op':'or','args':[{'condition':'a'},{'condition':'b'}]}]}
    assert attack_paths(expr)==[[('a',False),('b',False)]]
    assert attack_paths({'op':'or','args':[{'condition':'a'},{'op':'and','args':[{'condition':'a'},{'condition':'b'}]}]})==[[('a',True)]]
    with pytest.raises(ValueError,match='satisfiable'):
        attack_paths({'op':'and','args':[{'condition':'a'},{'op':'not','args':[{'condition':'a'}]}]})


def test_path_explosion_is_bounded():
    expr={'op':'and','args':[{'op':'or','args':[{'condition':f'a{i}'},{'condition':f'b{i}'}]} for i in range(9)]}
    with pytest.raises(ValueError,match='256'):attack_paths(expr)


def test_exception_paths_keep_individual_questions():
    reviews,records=population()
    result=build_workflow(reviews,records,k=1,similarity_threshold=1)
    assert result['clustering']['exception_count']>0
    assert not result['plan']['common_questions']
    assert all(c['specific_questions'] for c in result['plan']['cves'])


def test_semantic_mode_uses_condition_text_without_product_metadata(monkeypatch):
    import numpy as np
    from src import prerequisite_models
    seen=[]
    def encode(texts):
        seen.extend(texts)
        return np.array([[1,0],[0,1],[1,0]],dtype=float),'synthetic-test-encoder'
    monkeypatch.setattr(prerequisite_models,'embed_conditions',encode)
    reviews,records=population()
    for r in reviews:r['manufacturer']='PRIVATE_VENDOR';r['product']='PRIVATE_PRODUCT'
    result=build_workflow(reviews,records,k=2,embedding_mode='semantic')
    assert result['clustering']['embedding']=='synthetic-test-encoder'
    assert all('PRIVATE_' not in text and 'SIM-' not in text for text in seen)


@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(review_store,'DB',tmp_path/'sessions.sqlite3')
    app=FastAPI();app.include_router(api.router)
    from src.question_mining_api import router
    app.include_router(router)
    return TestClient(app)


def test_api_compile_preserves_unknown_attacker_possession(client):
    loaded=client.post('/api/operational-workflow/source',json=dict(cve='TEST-1',source='synthetic fixture',text='Administrator privileges are required.')).json()
    text=loaded['record']['sources'][0]['text']
    condition=dict(id='priv',predicate='attacker_has_required_privilege',target='web interface',value='administrator',
        source_refs=[dict(source_id='advisory',quote=text,span=[0,len(text)])])
    response=client.post('/api/operational-workflow/compile',json=dict(reviewer='Synthetic test',review_confirmed=True,
        reviews=[dict(source_id=loaded['source_id'],conditions=[condition],formula={'condition':'priv'},coverage_complete=False)]))
    assert response.status_code==200,response.text
    saved=response.json()
    assert saved['plan']['cves'][0]['unresolved_condition_ids']==['priv']
    assert not saved['plan']['cves'][0]['specific_questions']
    assert saved['plan']['reviews'][0]['conditions'][0]['operator_observable'] is False
    result=client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=dict(
        scope=dict(asset_ref='A',product='P',build='1',config_baseline='C',mode='normal'),answers=[]))
    assert result.status_code==200,result.text
    assert result.json()['decisions'][0]['formula_value']=='unknown'


def test_unconfigured_llm_reports_error_without_claiming_extraction(client,monkeypatch):
    monkeypatch.delenv('ICS_PREREQUISITE_LLM_URL',raising=False)
    response=client.post('/api/operational-workflow/source',json=dict(cve='TEST',source='fixture',text='A condition.',extraction_mode='llm'))
    assert response.status_code==422
    assert 'ICS_PREREQUISITE_LLM_URL' in response.json()['detail']


def test_llm_drafts_require_exact_unique_quotes_and_preserve_nonrequirements(monkeypatch):
    from src.prerequisite_models import extract_conditions
    monkeypatch.setenv('ICS_PREREQUISITE_LLM_URL','http://fixture.invalid/chat')
    monkeypatch.setenv('ICS_PREREQUISITE_LLM_MODEL','synthetic-model')
    text='Network access is required. Authentication is not required.'
    record=dict(cve='TEST',sources=[dict(id='s',text=text)])
    draft=dict(conditions=[dict(id='c1',predicate='network_reachable',target='web interface',value='',explicitness='explicit',
        source_refs=[dict(source_id='s',quote='Network access is required.')])],formula={'condition':'c1'},
        nonrequirements=[dict(predicate='authentication_required',source_id='s',quote='Authentication is not required.')],unknowns=['user interaction'])
    class Response:
        def raise_for_status(self):pass
        def json(self):return {'choices':[{'message':{'content':json.dumps(draft)}}]}
    monkeypatch.setattr('requests.post',lambda *args,**kw:Response())
    result=extract_conditions(record)
    assert result['validation_status']=='pending_review'
    assert result['nonrequirements'][0]['span']==[28,len(text)]
    assert len(result['conditions'])==1
    draft['conditions'][0]['source_refs'][0]['quote']='Invented condition'
    with pytest.raises(ValueError,match='quotation'):extract_conditions(record)


@pytest.mark.parametrize('bom_format',['CycloneDX','SPDX'])
def test_bom_to_context_export_preserves_inventory_and_component_scope(client,monkeypatch,bom_format):
    from src import candidate_web
    from datetime import datetime,timedelta,timezone
    bom=(dict(bomFormat='CycloneDX',specVersion='1.5',version=1,components=[
        {'type':'library','bom-ref':ref,'name':'controller-lib','version':'1'} for ref in ('a','b')])
        if bom_format=='CycloneDX' else dict(spdxVersion='SPDX-2.3',SPDXID='SPDXRef-DOCUMENT',packages=[
            dict(SPDXID=ref,name='controller-lib',versionInfo='1') for ref in ('a','b')]))
    original=deepcopy(bom)
    job=dict(status='completed',input_sbom=bom,result=dict(components=[dict(
        component=dict(id=ref,name='controller-lib',version='1'),cves=[dict(cve_id=cve,match_status='match')
        for cve in ('CVE-2026-11111','CVE-2026-22222')]) for ref in ('a','b')]))
    monkeypatch.setattr(candidate_web,'get_job',lambda _:job)
    loaded=client.post('/api/operational-workflow/source',json=dict(cve='CVE-2026-11111',source='fixture',text='Network access required.')).json()
    compiled=client.post('/api/operational-workflow/compile',json=dict(reviewer='Synthetic reviewer',review_confirmed=True,
        identification_job_id='synthetic-job',reviews=[dict(source_id=loaded['source_id'],conditions=[dict(
            id='net',predicate='network_reachable',target='management',source_refs=[dict(source_id='advisory',span=[0,24],quote='Network access required.')])],
            formula={'condition':'net'},coverage_complete=False)]))
    assert compiled.status_code==200,compiled.text
    saved=compiled.json();now=datetime.now(timezone.utc)
    response=client.post('/api/question-mining/reviews/'+saved['id']+'/answers',json=dict(
        scope=dict(asset_ref='a',product='controller-lib',build='1',config_baseline='A',mode='normal'),answers=[],
        observed_at=(now-timedelta(minutes=1)).isoformat(),valid_until=(now+timedelta(days=1)).isoformat(),
        product_assertion=dict(status='affected',cves=['CVE-2026-11111'],source='Synthetic supplier assertion',
                               quote='This exact product/build is affected.',action_statement='Synthetic update action')))
    assert response.status_code==200,response.text
    result=response.json();context=result['context_bom']
    assert context['input_bom']==original==bom
    assert context['unreviewed_cves']==['CVE-2026-22222']
    assert context['coverage']==dict(candidate_cves=2,reviewed_cves=1,component_links=4,assessed_component_links=1)
    statuses={(r['cve'],r['component_ref']):r['status'] for r in context['component_assessments']}
    assert statuses[('CVE-2026-11111','a')]=='affected'
    assert statuses[('CVE-2026-11111','b')]=='under_investigation'
    if bom_format=='CycloneDX':
        assert context['cyclonedx_validation']['status']=='valid',context['cyclonedx_validation']
        assert context['unbound_component_links']==0
        assert len(context['cyclonedx']['vulnerabilities'])==4
    else:assert 'cyclonedx' not in context
    restored=client.get('/api/question-mining/reviews/'+saved['id']).json()
    assert restored['last_evaluation']['context_bom']==context


def test_dashboard_embeds_bom_and_context_workflows_with_unique_ids():
    import re
    from src.api_server import make_page
    html=make_page('analyzer')
    # Inspect markup independently of JavaScript-generated template strings.
    from bs4 import BeautifulSoup
    page=BeautifulSoup(html,'html.parser')
    ids=[tag['id'] for tag in page.find_all(id=True)]
    assert len(ids)==len(set(ids))
    assert page.find(id='candidate-workspace') and page.find(id='operational-workspace')
    assert page.find(id='ow-candidateQueue')
    assert 'icsvex:operational-handoff' in html and 'Download Context BOM' in html
