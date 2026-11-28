"""Adaptive navigation preserves source three-valued logic and evidence gates."""
from copy import deepcopy
from itertools import product
import json
from pathlib import Path
import subprocess
from unittest.mock import patch
import pytest
from src.item4.analysis import operating_question_tree as T
from src.item4.decision.condition_logic_evaluation import logic
from src.item4.workflow import source_analysis_jobs as Q
from tests.item4.test_item4_asset_key_workflow import fixture_job


def plan(expression):
    return dict(expression=expression,condition_order=['a','b','c'],
        questions={c:dict(id='q-'+c,label=c,positive_fact=c+' is enabled') for c in 'abc'},
        standalone_condition_ids=[],unavailable_condition_ids=[],source_unknowns=[])


@pytest.mark.parametrize('op',['and','or'])
def test_decisive_answer_skips_only_irrelevant_questions(op):
    p=plan(dict(op=op,args=[dict(condition='a'),dict(condition='b')]))
    decisive='x' if op=='and' else 'o'
    s=T.snapshot(p,{'q-a':decisive},['q-a'])
    assert s['next_question_id'] is None and 'b' in s['skipped_condition_ids']
    assert s['final_vex_decision'] is False
    assert T.snapshot(p,{'q-a':'o' if op=='and' else 'x'},['q-a'])['next_question_id']=='q-b'


def test_unknown_continues_and_can_still_be_resolved_by_another_answer():
    p=plan(dict(op='and',args=[dict(condition='a'),dict(condition='b')]))
    assert T.snapshot(p,{},[])['next_question_id']=='q-a'
    assert T.snapshot(p,{'q-a':'unknown'},['q-a'])['next_question_id']=='q-b'
    assert T.snapshot(p,{'q-a':'unknown','q-b':'x'},['q-a','q-b'])['value']=='false'
    s=T.snapshot(p,{'q-a':'unknown','q-b':'o'},['q-a','q-b'])
    assert s['value']=='unknown' and s['next_question_id'] is None


def test_not_preserves_positive_question_and_shared_identity():
    p=plan(dict(op='not',args=[dict(condition='a')]))
    before=deepcopy(p)
    assert T.snapshot(p,{'q-a':'o'},['q-a'])['value']=='false'
    assert T.snapshot(p,{'q-a':'x'},['q-a'])['value']=='true'
    assert p==before
    p['expression']=dict(op='or',args=[dict(condition='a'),dict(condition='a')])
    assert T.snapshot(p,{},[])['next_question_id']=='q-a'
    assert T.snapshot(p,{'q-a':'unknown'},['q-a'])['next_question_id'] is None


def test_unavailable_questions_stay_unknown_and_do_not_block_other_useful_questions():
    p=plan(dict(op='and',args=[dict(condition='missing'),dict(condition='b')]))
    assert T.snapshot(p,{},[])['next_question_id']=='q-b'
    assert T.snapshot(p,{'q-b':'o'},['q-b'])['value']=='unknown'
    assert T.snapshot(p,{'q-b':'x'},['q-b'])['value']=='false'


def test_case_scoping_and_alternative_scenarios_are_preserved():
    job,_=fixture_job();case=job['assessment_cases'][0];draft=job['conditions'][0]['prerequisite']['draft']
    draft['scenarios'].append(dict(id='another',expression=dict(op='not',args=[dict(condition='http')]),product_keys=[]))
    other=dict(case,id='other-case',declared_ref='other')
    before=deepcopy(draft)
    trees=T.build(job,[case,other],job['asset_questions'])
    assert trees[0]['expression']==dict(op='or',args=[s['expression'] for s in draft['scenarios']])
    assert trees[1]['questions']=={} and trees[1]['unavailable_condition_ids']==['http']
    assert draft==before


def test_unplaced_conditions_never_get_an_invented_and_relation():
    job,_=fixture_job();case=job['assessment_cases'][0]
    job['conditions'][0]['prerequisite']['draft']['scenarios']=[]
    p=T.build(job,[case],job['asset_questions'])[0]
    assert p['expression'] is None and p['standalone_condition_ids']==['http']
    s=T.snapshot(p,{job['asset_questions'][0]['id']:'o'})
    assert s['value']=='unknown' and s['relationship_unresolved']


def test_javascript_navigation_matches_server_truth_tables():
    expressions=[dict(condition='a'),dict(op='not',args=[dict(condition='a')]),
        dict(op='and',args=[dict(condition='a'),dict(condition='b')]),
        dict(op='or',args=[dict(condition='a'),dict(condition='b')]),
        dict(op='and',args=[dict(condition='a'),dict(op='or',args=[dict(condition='b'),dict(op='not',args=[dict(condition='c')])])])]
    cases=[]
    for expression in expressions:
        p=plan(expression)
        for values in product(['o','x','unknown','mixed','not_applicable'],repeat=3):
            answers=dict(zip(['q-a','q-b','q-c'],values))
            for asked in ([],['q-a'],['q-a','q-b','q-c']):
                expected=T.snapshot(p,answers,asked)
                facts={c:{'o':'true','x':'false'}.get(answers['q-'+c],'unknown') for c in 'abc'}
                assert expected['value']==logic(expression,facts)
                cases.append(dict(plan=p,answers=answers,asked=asked,expected=expected))
    module=Path(__file__).resolve().parents[2]/'src/item4/web/operating_question_tree.js'
    code='const T=require(process.argv[1]);let s="";process.stdin.on("data",x=>s+=x);process.stdin.on("end",()=>{for(const c of JSON.parse(s)){const actual=T.snapshot(c.plan,c.answers,c.asked);if(JSON.stringify(actual)!==JSON.stringify(c.expected))throw Error(JSON.stringify({actual,expected:c.expected}));}console.log("matched");});'
    result=subprocess.run(['node','-e',code,str(module)],input=json.dumps(cases),capture_output=True,text=True,timeout=20)
    assert result.returncode==0,result.stderr
    assert result.stdout.strip()=='matched'


def test_explicit_unknown_progress_is_saved_and_stale_ids_are_rejected(tmp_path,monkeypatch):
    job,_=fixture_job();qid=job['asset_questions'][0]['id']
    monkeypatch.setattr(Q.store,'DB',tmp_path/'jobs.sqlite3');monkeypatch.setattr(Q,'JOBS',{})
    monkeypatch.setattr(Q,'extraction_identity',lambda:job['extraction_identity'])
    Q._save(job)
    token=dict(revision=job['revision'],plan_sha256=job['plan_sha256'])
    saved=Q.save_answers(job['id'],dict(token,answers={qid:'unknown'},asked_question_ids=[qid]))
    assert saved['asked_question_ids']==[qid] and saved['answers'][qid]=='unknown'
    assert Q.get(job['id'])['asked_question_ids']==[qid]
    for ids in (['stale'],[qid,qid],[{}]):
        with pytest.raises(ValueError,match='unique current question IDs'):
            Q.save_answers(job['id'],dict(revision=saved['revision'],plan_sha256=saved['plan_sha256'],asked_question_ids=ids))


def test_live_page_loads_tree_dependency_before_questionnaire():
    from fastapi.testclient import TestClient
    from tools.item4.serve_nist_operational_vex import app
    with TestClient(app) as client:
        page=client.get('/item4.html').text
        assert page.index('src="/item4-question-tree.js')<page.index('src="/item4-questionnaire.js')
        script=client.get('/item4-question-tree.js')
        assert script.status_code==200 and 'Item4QuestionTree' in script.text
