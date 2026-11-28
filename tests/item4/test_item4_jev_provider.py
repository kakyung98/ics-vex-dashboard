from copy import deepcopy
from types import SimpleNamespace

import pytest

from src.item4.models import constrained_choice_provider as jev
from src.item4.models import scenario_review_experts as moe
from src.item4.models import json_inference_client as llm


def packet():
    return dict(expert='inventory', evidence={'e0': {'deployment': 'running'}},
                schema={'properties': {'finding': {'enum': list(moe.CHOICES['inventory'])},
                                       'cite': {'enum': ['e0', 'none']}}})


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv('TYPESAFE_API_KEY', 'test-key')
    monkeypatch.setenv('ICS_ITEM4_REVIEW_PROVIDER', 'typesafe_jev')
    for name in ('ICS_JEV_MODEL', 'ICS_JEV_MIN_CONFIDENCE', 'ICS_JEV_MIN_PROBABILITY'):
        monkeypatch.delenv(name, raising=False)
    calls = []
    response = {}

    def post(url, **kwargs):
        calls.append((url, kwargs))
        options = kwargs['json']['questions']['review']['criteria']
        selected = next(k for k, v in options.items() if v == dict(finding='installed_exact', cite='e0'))
        probabilities = {k: float(k == selected) for k in options}
        result = dict(model='jev-1.14.0', answers={'review': dict(type='choice', choice=selected,
                      confidence=0.95, probabilities=probabilities)}, usage={'input_tokens': 100})
        response['result'] = result
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: deepcopy(result))

    import requests
    monkeypatch.setattr(requests, 'post', post)
    return calls, response


def test_role_routing_and_coupled_citation(api):
    assert llm.identity('operating-record-review')['provider'] == 'typesafe_jev'
    assert not jev.enabled('exploitation-prerequisites')
    output = llm.generate('Review inventory.', packet(), role='operating-record-review')
    assert output['prediction'] == dict(finding='installed_exact', cite='e0')
    assert output['decision']['accepted'] is True
    calls, _ = api
    assert calls[0][0] == jev.ENDPOINT
    criteria = calls[0][1]['json']['questions']['review']['criteria']
    assert dict(finding='installed_exact', cite='none') not in criteria.values()


@pytest.mark.parametrize('corruption', ['confidence', 'probabilities', 'choice', 'model'])
def test_invalid_responses_never_become_findings(api, monkeypatch, corruption):
    import requests
    original = requests.post

    def corrupt(*args, **kwargs):
        response = original(*args, **kwargs)
        result = response.json()
        if corruption == 'model':
            result['model'] = 'other-model'
        else:
            result['answers']['review'][corruption] = {
                'confidence': float('nan'), 'probabilities': {}, 'choice': 'invented'}[corruption]
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: result)

    monkeypatch.setattr(requests, 'post', corrupt)
    with pytest.raises(ValueError):
        jev.generate('review', packet(), role=moe.INFERENCE_ROLE)


def test_low_confidence_and_cached_receipt(api, monkeypatch):
    monkeypatch.setenv('ICS_JEV_MIN_CONFIDENCE', '0.99')
    cache = {}
    rows = [('inventory-1', {'deployment': 'running'})]
    first = moe._expert('inventory', rows, None, cache)
    second = moe._expert('inventory', rows, None, cache)
    assert first['verdict'] == 'unresolved'
    assert first['decision']['accepted'] is False
    assert second['decision'] == first['decision']
    assert second['execution'] == 'cached'
    assert len(api[0]) == 1
    monkeypatch.setenv('ICS_JEV_MIN_CONFIDENCE', '0.8')
    assert moe._expert('inventory', rows, None, cache)['verdict'] == 'installed_exact'
    assert len(api[0]) == 2


def test_conflict_cites_group_as_one_option():
    item = dict(expert='supplier', evidence={'e0': {}, 'e1': {}}, citation_groups={'group0': ['e0', 'e1']},
                schema={'properties': {'assessment': {'enum': ['conflicting_group0', 'unresolved']}}})
    body, options, fallback = jev.build_request('review', item)
    assert dict(assessment='conflicting_group0') in options.values()
    assert body['state']['citation_groups']['group0'] == ['e0', 'e1']
    assert fallback == dict(assessment='unresolved')


def test_batch_routes_without_local_gpu_and_isolates_errors(api):
    from src.item4.models.expert_batch_inference import generate_model_batch
    outputs = generate_model_batch([dict(system='review', packet=packet()),
                                    dict(system='review', packet={'expert': 'unsupported'})])
    assert outputs[0]['model']['provider'] == 'typesafe_jev'
    assert isinstance(outputs[1], ValueError)


def test_missing_key_never_calls_api(api, monkeypatch):
    monkeypatch.delenv('TYPESAFE_API_KEY')
    receipt = moe._expert('inventory', [('obs', {})], None, {})
    assert receipt['execution'] == 'error'
    assert receipt['verdict'] is None
    assert not api[0]
