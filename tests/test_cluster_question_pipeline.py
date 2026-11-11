"""Behavioral counterexamples for shared answers and CVE-specific residuals."""
import copy
import pytest

from src.cluster_question_pipeline import (compile_plan, evaluate_plan, export_openvex,
    draft_question, screen_candidate, SCOPE)
from src.context_vex_pipeline import logic

APPROVED=dict(validation_status='approved',reviewer='synthetic-fixture-only',reviewed_at='2026-01-02T00:00:00Z')


def fixture():
    records=[];reviews=[];memberships=[];cases=[]
    for cve,operator,special in [('SIM-A','and','feature'),('SIM-B','or','file')]:
        text=f'CONTROLLED SYNTHETIC: {cve} has exactly the stated {operator} formula; not real CVE evidence.'
        source=dict(id=cve+':source',text=text)
        ref=dict(source_id=source['id'],span=[0,len(text)],quote=text)
        records.append(dict(cve=cve,sources=[source]))
        conditions=[];questions=[]
        for cid,target,predicate,prompt in [
            ('network','controller:service:443','network_reachable','Is the controller service reachable?'),
            (special,'controller:'+special,special+'_present','Is '+special+' present?')]:
            conditions.append(dict(id=cid,target=target,predicate=predicate,necessity='required_for_path',
                operator_observable=True,source_refs=[ref],**APPROVED))
            questions.append(dict(id=cve+':'+cid,text=prompt,target=target,cost=1,**APPROVED,
                mappings=[dict(condition_id=cid,coverage='FULL',answers=dict(yes='true',no='false',unknown='unknown'),
                               source_refs=[ref],**APPROVED)]))
        reviews.append(dict(cve=cve,conditions=conditions,questions=questions,
            formula=dict(expression=dict(op=operator,args=[{'condition':'network'},{'condition':special}]),
                         coverage_complete=True,source_refs=[ref],**APPROVED)))
        memberships.append(dict(cve=cve,cluster_ids=['secondary:1']))
        binding=dict(cve=cve,asset_ref='asset',product='controller',build='1',config_baseline='normal',
                     mode='running',evaluated_at='2026-02-01T00:00:00Z')
        def evidence(eid,kind):
            return dict(id=eid,kind=kind,binding=binding,source='synthetic-fixture',quote='Explicit synthetic record only',
                        reviewer='synthetic-fixture-only',observed_at='2026-01-01T00:00:00Z',
                        reviewed_at='2026-01-02T00:00:00Z',valid_until='2027-01-01T00:00:00Z')
        cases.append(dict(binding=binding,answers=[],formula_evidence_ids=['complete'],
            evidence=[evidence('complete','reviewed_complete_route_analysis'),
                      evidence('network','reviewed_nonexecution_analysis'),evidence(special,'reviewed_nonexecution_analysis')]))
    return reviews,records,memberships,cases


def shared_answer(plan,cases,value='no'):
    q=plan['common_questions'][0]
    return dict(plan_id=plan['plan_id'],question_id=q['id'],target=q['target'],value=value,
                scope={k:cases[0]['binding'][k] for k in SCOPE},
                evidence_by_cve={c['binding']['cve']:['network'] for c in cases})


def test_common_question_and_logical_specific_residuals():
    reviews,records,members,cases=fixture()
    plan=compile_plan(reviews,records,members)
    assert len(plan['common_questions'])==1
    assert len(plan['common_questions'][0]['members'])==2
    assert [len(c['specific_questions']) for c in plan['cves']]==[1,1]
    result=evaluate_plan(plan,records,cases,[shared_answer(plan,cases)])
    assert [r['status'] for r in result['decisions']]==['not_affected','under_investigation']
    assert [r['formula_value'] for r in result['decisions']]==['false','unknown']
    assert len(result['propagated_answers'])==2
    assert result['decisions'][0]['next_specific_questions']==[]
    assert [q['id'] for q in result['decisions'][1]['next_specific_questions']]==['SIM-B:file']
    # A false common condition refutes AND, but does not erase an OR alternative.
    cases[1]['answers'].append(dict(question_id='SIM-B:file',value='no',evidence_ids=['file']))
    assert [r['status'] for r in evaluate_plan(plan,records,cases,[shared_answer(plan,cases)])['decisions']]==['not_affected']*2


@pytest.mark.parametrize('difference',['cluster','target','text','polarity','unreviewed'])
def test_similar_questions_are_not_unconditionally_shared(difference):
    reviews,records,members,_=fixture()
    if difference=='cluster':members[1]['cluster_ids']=['secondary:2']
    if difference=='target':
        reviews[1]['conditions'][0]['target']='other-service'
        reviews[1]['questions'][0]['target']='other-service'
    if difference=='text':reviews[1]['questions'][0]['text']='Is a different network route reachable?'
    if difference=='polarity':reviews[1]['questions'][0]['mappings'][0]['answers'].update(yes='false',no='true')
    if difference=='unreviewed':reviews[1]['questions'][0]['mappings'][0]['validation_status']='pending_review'
    assert compile_plan(reviews,records,members)['common_questions']==[]


@pytest.mark.parametrize('field',['asset_ref','product','build','config_baseline','mode','evaluated_at'])
def test_shared_answer_never_crosses_asset_scope(field):
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    answer=shared_answer(plan,cases)
    cases[1]['binding']={**cases[1]['binding'],field:'different'}
    result=evaluate_plan(plan,records,cases,[answer])
    assert len(result['propagated_answers'])==1
    assert result['rejected_propagations'][0]['cve']=='SIM-B'
    assert result['decisions'][1]['status']=='under_investigation'


def test_common_answer_needs_separate_cve_evidence_and_unknown_is_unknown():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    answer=shared_answer(plan,cases,'unknown');answer['evidence_by_cve'].pop('SIM-B')
    result=evaluate_plan(plan,records,cases,[answer])
    assert all(r['status']=='under_investigation' for r in result['decisions'])
    assert result['decisions'][0]['condition_values']['network']=='unknown'
    assert len(result['rejected_propagations'])==1


def test_conflicting_common_and_specific_answers_remain_visible():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    cases[0]['answers']=[dict(question_id='SIM-A:network',value='yes',evidence_ids=['network'])]
    result=evaluate_plan(plan,records,cases,[shared_answer(plan,cases)])
    assert result['decisions'][0]['status']=='under_investigation'
    assert result['decisions'][0]['answer_conflicts']==['network']


def test_stale_plan_wrong_target_and_modified_sources_are_rejected():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    for field in ('plan_id','target'):
        answer=shared_answer(plan,cases);answer[field]='wrong'
        with pytest.raises(ValueError):evaluate_plan(plan,records,cases,[answer])
    changed=copy.deepcopy(records);changed[0]['sources'][0]['text']='changed'
    with pytest.raises(ValueError):evaluate_plan(plan,changed,cases)
    plan['common_questions'][0]['target']='changed'
    with pytest.raises(ValueError):evaluate_plan(plan,records,cases)


def test_no_formula_is_invented_and_drafts_are_not_self_approved():
    reviews,records,members,cases=fixture()
    reviews[0]['formula']=None
    reviews[0]['questions']=[draft_question(reviews[0]['conditions'][0])]
    assert reviews[0]['questions'][0]['validation_status']=='pending_review'
    plan=compile_plan(reviews,records,members)
    assert plan['cves'][0]['formula'] is None
    assert evaluate_plan(plan,records,cases)['decisions'][0]['formula_value']=='unknown'
    with pytest.raises(ValueError):draft_question(dict(id='x',predicate='feature_enabled',target='unresolved'))


def test_true_answers_need_impact_proof_and_export_contains_exact_scope():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    for case in cases:
        special='feature' if case['binding']['cve']=='SIM-A' else 'file'
        case['answers']=[dict(question_id=case['binding']['cve']+':'+special,value='yes',evidence_ids=[special])]
    answer=shared_answer(plan,cases,'yes')
    assert all(r['status']=='under_investigation' for r in evaluate_plan(plan,records,cases,[answer])['decisions'])
    e=copy.deepcopy(cases[1]['evidence'][0]);e.update(id='supplier',kind='supplier_product_status',asserted_status='affected')
    cases[1]['evidence'].append(e)
    cases[1]['product_findings']=[dict(status='affected',evidence_ids=['supplier'],action_statement='Apply the synthetic fixture fix.')]
    result=evaluate_plan(plan,records,cases,[answer])
    assert result['decisions'][1]['status']=='affected'
    doc=export_openvex(result,'synthetic demo','2026-02-01T00:00:00Z')
    assert [s['status'] for s in doc['statements']]==['under_investigation','affected']
    assert doc['statements'][1]['action_statement']
    assert doc['statements'][0]['products']==doc['statements'][1]['products']
    assert doc['statements'][0]['timestamp']==cases[0]['binding']['evaluated_at']


def test_screening_retains_suspected_bad_conditions():
    row=dict(condition_id='x',cve='SIM-X',condition='Attacker can execute arbitrary code',necessity='explicitly_required')
    result=screen_candidate(row)
    assert result['retained'] and not result['semantic_verified']
    assert 'possible_consequence_mixed_with_precondition' in result['flags']


def test_known_formula_can_still_require_product_evidence():
    reviews,records,members,cases=fixture();plan=compile_plan(reviews,records,members)
    cases[0]['answers']=[dict(question_id='SIM-A:feature',value='yes',evidence_ids=['feature'])]
    result=evaluate_plan(plan,records,cases,[shared_answer(plan,cases,'yes')])['decisions'][0]
    assert result['formula_value']=='true'
    assert result['next_specific_questions']==[] and result['next_common_question_ids']==[]
    assert result['status']=='under_investigation' and result['missing_evidence']
