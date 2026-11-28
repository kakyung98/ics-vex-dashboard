from copy import deepcopy
import pytest
from src.item4.evaluation.sealed_source_gt import judge
from src.item4.evaluation.nemotron_source_synthetic import state_polarity


def fixture():
    span='maintenance operator has write permission'
    source='The maintenance operator has write permission before this path is usable. Authentication is not required.'
    fact=dict(id='a',aliases=['write permission'],kind='C5',polarity=True,necessity='required',actor='attacker',qualifiers=[['maintenance operator']],source='S0',evidence=[span])
    nr=dict(id='n',aliases=['authentication'],kind='C4',polarity=False,necessity='nonrequirement',source='S0',evidence=['Authentication is not required'])
    case=dict(passages={'S0':source},gold=dict(facts=[fact,nr],expression={'condition':'a'},branches=[dict(facts=['a'],source='S0',evidence=[source.split('. ')[0]])]))
    prediction=dict(conditions=[dict(id='p',target='write permission',state='maintenance operator has permission',necessity='required',actor='attacker',source='S0',quote=span),dict(id='n',target='authentication',state='not required',necessity='nonrequirement',actor='attacker',source='S0',quote='Authentication is not required')],scenarios=[dict(id='s',conditions=['p'],source='S0',quote=source.split('. ')[0])],unknowns_ko='none',complete=True)
    return case,prediction


def test_positive_evidence_contract():
    c,p=fixture();assert judge(c,p)['correct']


@pytest.mark.parametrize('bad',['maintenance operator has no permission','maintenance operator lacks permission','maintenance operator is not permitted','maintenance operator has unknown permission'])
def test_negative_or_unknown_permission_cannot_pass_positive(bad):
    c,p=fixture();p['conditions'][0]['state']=bad;assert not judge(c,p)['correct']


def test_nonrequirement_state_cannot_be_reversed():
    c,p=fixture();p['conditions'][1]['state']='required';assert not judge(c,p)['correct']


def test_relation_quote_must_cover_preannotated_relation():
    c,p=fixture();p['scenarios'][0]['quote']='this path';assert not judge(c,p)['correct']


def test_atom_quote_must_support_the_assertion_not_just_copy_a_name():
    c,p=fixture();p['conditions'][0]['quote']='write permission';assert not judge(c,p)['correct']


def test_contextual_hallucination_is_not_silently_ignored():
    c,p=fixture();p['conditions'].append(dict(id='ghost',target='firewall',state='disabled',necessity='contextual',actor='system',source='S0',quote='this path'))
    assert not judge(c,p)['correct']


def test_nonrequirement_must_not_be_a_scenario_gate():
    c,p=fixture();p['scenarios'][0]['conditions'].append('n');assert not judge(c,p)['correct']


def test_scope_and_duplicate_identity_are_required():
    c,p=fixture();p['conditions'][0]['state']='has permission';assert not judge(c,p)['correct']
    c,p=fixture();p['conditions'][1]['id']='p';assert not judge(c,p)['correct']


def test_not_required_is_not_the_same_as_disabled():
    assert state_polarity('enabled but not required','C1') is None


def test_unknown_paraphrase_fails_closed_without_changing_labels():
    c,p=fixture();before=deepcopy(c);p['conditions'][0]['state']='maintenance operator: possessive semantics unspecified'
    assert not judge(c,p)['correct'];assert c==before
