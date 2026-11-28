"""TypeSafe Choice adapter for the closed-set #4 expert contract only."""
from copy import deepcopy
import math
import os

ENDPOINT = 'https://api.typesafe.ai/v1/systemone'
VERSION = 'item4-jev/1'


def enabled(role='operating-record-review'):
    provider = os.getenv('ICS_ITEM4_REVIEW_PROVIDER', 'default')
    if provider not in ('default', 'typesafe_jev'):
        raise ValueError('Unknown ICS_ITEM4_REVIEW_PROVIDER')
    return role == 'operating-record-review' and provider == 'typesafe_jev'


def _probability(value):
    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError('Invalid Jev probability or confidence')
    return value


def identity():
    confidence = _probability(float(os.getenv('ICS_JEV_MIN_CONFIDENCE', '0.8')))
    probability = _probability(float(os.getenv('ICS_JEV_MIN_PROBABILITY', '0.8')))
    return dict(provider='typesafe_jev', model=os.getenv('ICS_JEV_MODEL', 'jev-1.14.0'),
                endpoint=ENDPOINT, adapter_version=VERSION, min_confidence=confidence,
                min_probability=probability, nli_used=False)


def build_request(system, packet, spec=None):
    """Choose a finding AND its citation together; never combine independent answers."""
    from src.item4.models.scenario_review_experts import CHOICES
    expert = packet.get('expert')
    if expert not in CHOICES:
        raise ValueError('Jev supports only #4 closed-set expert packets')
    properties = packet['schema']['properties']
    if set(properties) == {'assessment'}:
        if properties['assessment'].get('enum') != ['conflicting_group0', 'unresolved']:
            raise ValueError('Unsupported Jev conflict contract')
        values = [dict(assessment=value) for value in properties['assessment']['enum']]
        fallback = dict(assessment='unresolved')
    elif set(properties) == {'finding', 'cite'}:
        if properties['finding'].get('enum') != list(CHOICES[expert]):
            raise ValueError('Unsupported Jev finding contract')
        citations = properties['cite']['enum']
        if set(citations) != {*packet['evidence'], 'none'}:
            raise ValueError('Unsupported Jev citation contract')
        fallback = dict(finding='insufficient' if expert == 'crosscheck' else 'unresolved', cite='none')
        values = [dict(finding=finding, cite=cite)
                  for finding in CHOICES[expert] if finding != 'conflicting'
                  for cite in citations
                  if cite != 'none' or finding in ('unresolved', 'insufficient')]
    else:
        raise ValueError('Unsupported Jev expert schema')
    if not 1 <= len(values) <= 255:
        raise ValueError('Jev Choice limit exceeded; evidence was not truncated')
    options = {f'option_{index}': value for index, value in enumerate(values)}
    spec = spec or identity()
    body = dict(model=spec['model'], state={k: v for k, v in packet.items() if k != 'schema'},
                questions={'review': dict(type='choice', instructions=system +
                    ' Select the supported assessment and its supporting citation together. '
                    'Choose unresolved or insufficient when evidence is missing or ambiguous.',
                    criteria=options)})
    return body, options, fallback


def generate(system, packet, *, role):
    if role != 'operating-record-review':
        raise ValueError('Jev cannot generate extraction text')
    spec = identity()
    body, options, fallback = build_request(system, packet, spec)
    key = os.getenv('TYPESAFE_API_KEY')
    if not key:
        raise ValueError('TYPESAFE_API_KEY is required for Jev')
    import requests
    response = requests.post(ENDPOINT, headers={'Authorization': 'Bearer ' + key,
                             'Content-Type': 'application/json'}, json=body, timeout=(10, 120))
    response.raise_for_status()
    result = response.json()
    if result.get('model') != spec['model'] or set(result.get('answers', {})) != {'review'}:
        raise ValueError('Unexpected Jev model or answer IDs; use a pinned model')
    answer = result['answers']['review']
    selected = answer.get('choice')
    probabilities = answer.get('probabilities')
    if answer.get('type') != 'choice' or selected not in options or not isinstance(probabilities, dict):
        raise ValueError('Invalid Jev Choice answer')
    if set(probabilities) != set(options):
        raise ValueError('Jev probability options differ from the request')
    confidence = _probability(answer.get('confidence'))
    for value in probabilities.values():
        _probability(value)
    if abs(sum(probabilities.values()) - 1) > 0.01:
        raise ValueError('Jev probabilities are not normalized')
    probability = probabilities[selected]
    if probability < max(probabilities.values()) - 1e-6:
        raise ValueError('Jev choice does not have the highest probability')
    accepted = confidence >= spec['min_confidence'] and probability >= spec['min_probability']
    return dict(prediction=deepcopy(options[selected] if accepted else fallback), model=spec, llm_used=True,
                decision=dict(adapter_version=VERSION, selected=deepcopy(options[selected]),
                              confidence=confidence, probability=probability, accepted=accepted,
                              probabilities=deepcopy(probabilities), options=deepcopy(options),
                              usage=result.get('usage')))


def generate_batch(requests):
    """Return each request's error independently so other CVEs retain their results."""
    outputs = []
    for request in requests:
        try:
            outputs.append(generate(request['system'], request['packet'], role='operating-record-review'))
        except Exception as exc:
            outputs.append(exc)
    return outputs
