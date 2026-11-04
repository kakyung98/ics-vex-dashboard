from copy import deepcopy
from src.operational_guardrails import assessment_gate


def qa(value='yes',evidence='Configuration record'):
    return {'id':'q1','origin':'llm','question':'On this asset, is the documented service active?',
            'answer':{'value':value,'evidence':evidence}}


def gate(questions,version=True,refs=None):
    return assessment_gate({'assessment':'likely_affected','answer_refs':['q1'] if refs is None else refs},questions,
        valid=True,generation_valid=True,version_decided=version)


def test_unknown_version_and_operating_facts_counterfactuals():
    assert gate([qa()])['assessment']=='likely_affected'
    assert gate([qa()],version=False)['assessment']=='likely_cannot_determine'
    assert gate([qa('unknown','')])['assessment']=='likely_cannot_determine'
    assert gate([qa('yes','')])['assessment']=='likely_cannot_determine'
    patch={**qa(),'id':'patch','origin':'system'}
    assert gate([patch],refs=['patch'])['assessment']=='likely_cannot_determine'
    assert gate([qa(),patch],refs=['patch'])['assessment']=='likely_cannot_determine'


def test_conflicting_identical_operating_answers_are_deferred():
    a=qa();b=deepcopy(a);b['id']='q2';b['answer']['value']='no'
    result=gate([a,b])
    assert result['assessment']=='likely_cannot_determine'
    assert 'conflicting_answers_to_identical_question' in result['errors']
