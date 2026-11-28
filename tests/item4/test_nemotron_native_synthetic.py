from copy import deepcopy
import pytest
from src.item4.evaluation import metamorphic_synthetic as E
from src.item4.evaluation import nemotron_source_synthetic as N


def teacher(family,index=0):
    case=E.make_case(family,index);conditions=[]
    for key,g in case['gold']['atoms'].items():
        state=g['negative'] if family==4 else g['positive']
        conditions.append(dict(id=key,target=g['target'],state=state,actor='victim' if family==10 else 'unknown',
            source='S0',quote=state,axis='OTHER',necessity='required'))
    quote=case['gold']['evidence_quotes'][0] if case['gold']['evidence_quotes'] else ''
    keys=list(case['gold']['atoms'])
    branches=[['a','b'],['a','c']] if family==3 else [[k] for k in keys] if family==2 else [keys] if keys else []
    scenarios=[dict(id='s'+str(i),conditions=branch,source='S0',quote=quote) for i,branch in enumerate(branches)]
    if family==6:conditions.append(dict(id='nr',target='authentication',state='not required',actor='attacker',source='S0',quote='Authentication is not required',axis='PR',necessity='nonrequirement'))
    return case,dict(conditions=conditions,scenarios=scenarios,unknowns_ko='unspecified' if not keys else 'none',complete=True)


@pytest.mark.parametrize('family',range(12))
def test_native_contract_teacher_preserves_all_source_worlds(family):
    case,prediction=teacher(family)
    assert N.judge(case,prediction)['case_correct']


def test_disabled_required_condition_does_not_become_enabled():
    case,prediction=teacher(4);prediction['conditions'][0]['state']='enabled'
    assert not N.judge(case,prediction)['logic_correct']


def test_distributed_or_cannot_be_replaced_with_one_and_branch():
    case,prediction=teacher(3);prediction['scenarios']=prediction['scenarios'][:1]
    assert not N.judge(case,prediction)['logic_correct']


@pytest.mark.parametrize('family',[9,11])
def test_assessment_scope_cannot_be_dropped(family):
    case,prediction=teacher(family);prediction['conditions'][0]['state']=prediction['conditions'][0]['state'].replace('assessed ','')
    assert not N.judge(case,prediction)['case_correct']


def test_nonrequirement_and_citation_are_scored_separately():
    case,prediction=teacher(6);missing=deepcopy(prediction);missing['conditions']=missing['conditions'][:1]
    assert N.judge(case,missing)['logic_correct'] and not N.judge(case,missing)['case_correct']
    prediction['conditions'][0]['quote']='fabricated quote'
    assert not N.judge(case,prediction)['evidence_correct']


def test_duplicate_ids_are_not_valid_logic():
    case,prediction=teacher(1);prediction['conditions'][1]['id']='a'
    assert not N.judge(case,prediction)['logic_correct']


def test_synthetic_only_gate_does_not_require_a_metamorphic_denominator():
    case,prediction=teacher(0)
    report=N.summarize([case],[dict(id=case['id'],phase='baseline',arm='native',prediction=prediction,valid=True)],synthetic_only=True)
    score=report['scores']['baseline/native/dev']
    assert score['above_90'] and score['grounded_mr_rate'] is None


def test_high_atom_f1_cannot_hide_a_nonrequirement_in_a_scenario_gate():
    case,prediction=teacher(6);prediction['scenarios'][0]['conditions'].append('nr')
    report=N.summarize([case],[dict(id=case['id'],phase='baseline',arm='native',prediction=prediction,valid=True)],synthetic_only=True)
    score=report['scores']['baseline/native/dev']
    assert score['f1']==1 and not score['above_90']
