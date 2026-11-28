"""Role names stay consistent across routing, grounded contracts and API results."""
import pytest

from src.item3.agents.agent_contracts import validate
from src.item3.agents.agent_message_format import KEYS; from src.item3.agents.agent_message_format import decode; from src.item3.agents.agent_message_format import encode
from src.item3.evidence.product_candidate_search import ProductIndex
from src.item3.matching.identification_pipeline import run_unified


@pytest.mark.parametrize('task,prediction', [
    ('I1', {'ranked_candidate_ids': ['identity-1'], 'evidence_refs': ['input:name', 'dictionary:identity-1'], 'status': 'ranked'}),
    ('I2', {'version_observation_ids': ['observation:0'], 'model_observation_ids': [], 'evidence_refs': ['observation:0'], 'status': 'supported'}),
    ('I3', {'candidate_id': 'identity-1', 'evidence_refs': ['input:name', 'dictionary:identity-1'], 'status': 'validated'}),
])
def test_public_role_contract_survives_wire_roundtrip(task, prediction):
    packet = {
        'candidates': [{'candidate_id': 'identity-1', 'conflicts': [], 'eligible_for_selection': True}],
        'observations': [{'id': 'observation:0', 'source': 'version', 'may_be_model_identifier': False}],
        'evidence': [{'id': 'input:name'}, {'id': 'dictionary:identity-1'}, {'id': 'observation:0'}],
    }
    assert validate(task, packet, prediction)
    _, _, response_schema, reverse = encode(task, packet)
    aliases = {original: short for short, original in reverse.items()}

    def shorten(value):
        if isinstance(value, list):
            return [shorten(v) for v in value]
        return aliases.get(value, value) if isinstance(value, str) else value

    response = {KEYS.get(key, key): shorten(value) for key, value in prediction.items()}
    from jsonschema import Draft202012Validator
    Draft202012Validator(response_schema).validate(response)
    assert decode(response, reverse) == prediction


def test_conditional_pipeline_uses_public_roles_throughout_result():
    index = ProductIndex([{'cpe': 'cpe:2.3:a:openssl:openssl:1.0.1g:*:*:*:*:*:*:*', 'title': 'OpenSSL'}])
    calls = []

    def infer(task, packet):
        calls.append(task)
        prediction = {
            'I1': {'ranked_candidate_ids': [], 'evidence_refs': [], 'status': 'unresolved'},
            'I2': {'version_observation_ids': [], 'model_observation_ids': [], 'evidence_refs': [], 'status': 'unresolved'},
            'I3': {'candidate_id': None, 'evidence_refs': [], 'status': 'unresolved'},
        }[task]
        return {'prediction': prediction, 'llm_used': False}

    class NoCVEs:
        def get_all(self, *args, **kwargs):
            return {'vulnerabilities': []}

    sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.7', 'components': [{
        'type': 'library', 'name': 'OpenSSX', 'version': 'version 1.0.1g',
        'manufacturer': {'name': 'openssl'},
        'cpe': 'cep:2.3:a:openssl:openssl:1.0.1g:*:*:*:*:*:*:*',
    }]}
    result = run_unified(sbom, NoCVEs(), index=index, mode='agents', agents=infer)
    # A misspelled product and malformed CPE have no independently supported
    # identity. Only the version review can add information at this point.
    assert calls == ['I2']
    assert result['agent_execution_order'] == calls
    row = result['components'][0]
    assert set(row['execution']) == {'i1', 'i2', 'i3'}
    assert set(row['routing']['decisions']) == {'I1', 'I2', 'I3'}
    assert row['validation']['status']=='unresolved'
    assert row['routing']['skipped_agents']==['I1','I3']
    for role in calls:
        record = row[role.lower()]['agent']
        assert record['task'] == role
        assert record['guard_accepted']
    assert not any('error' in row[role]['agent'] for role in ('i1', 'i2', 'i3'))


def test_historical_result_aliases_do_not_change_source_product_or_noise():
    from copy import deepcopy
    from src.item3.agents.agent_role_labels import canonical_roles
    source = {
        'input_sbom': {'components': [{'name': 'L2 controller', 'version': 'l3'}]},
        'result': {'components': [{'l2': {'agent': {'task': 'L2'}}, 'l3': {'normalized': '1.2'},
                                   'l4': {}, 'component': {'name': 'l2'}}],
                   'agent_execution_order': ['L2', 'L3', 'L4']},
        'perturbation': {'before': 'L2', 'after': 'L3'},
    }
    before = deepcopy(source)
    result = canonical_roles(source)
    assert source == before
    assert result['input_sbom'] == source['input_sbom']
    assert result['perturbation'] == source['perturbation']
    assert result['result']['agent_execution_order'] == ['I1', 'I2', 'I3']
    row = result['result']['components'][0]
    assert set(row) == {'i1', 'i2', 'i3', 'component'}
    assert row['i1']['agent']['task'] == 'I1'
    assert row['i2']['normalized'] == '1.2'
    assert row['component']['name'] == 'l2'


def test_previous_public_roles_are_normalized_without_renaming_source_products():
    from src.item3.agents.agent_role_labels import canonical_roles
    old = {'result': {'agent_execution_order': ['P2', 'P3', 'P4'],
                      'components': [{'p2': {'agent': {'task': 'P2'}},
                                      'p3': {'normalized': '1.2'}, 'p4': {},
                                      'component': {'name': 'Productivity P3-550E', 'purl': 'pkg:generic/p2@1.2'}}]},
           'input_sbom': {'components': [{'name': 'P2 controller', 'version': 'P3'}]}}
    new = canonical_roles(old)
    assert new['result']['agent_execution_order'] == ['I1', 'I2', 'I3']
    assert new['result']['components'][0]['i1']['agent']['task'] == 'I1'
    assert new['result']['components'][0]['component'] == old['result']['components'][0]['component']
    assert new['input_sbom'] == old['input_sbom']
    assert canonical_roles(new) == new


def test_previous_c_roles_are_read_as_i_roles_without_changing_evidence():
    from copy import deepcopy
    from src.item3.agents.agent_role_labels import canonical_roles
    saved = {'agent_execution_order': ['C1', 'C2', 'C3'],
             'llm_role': 'grounded_C1_C2_C3_evidence_review',
             'components': [{'c1': {'agent': {'task': 'C1'}},
                             'c2': {'observations': []}, 'c3': {},
                             'component': {'name': 'C1 controller', 'version': 'C2'},
                             'validation': {'reasons': ['C3_agent_not_confirmed']}}],
             'input_sbom': {'components': [{'name': 'C3 controller'}]},
             'gold': {'source_quote': 'C1 controller'},
             'perturbation': {'before': 'C1', 'after': 'C2'}}
    original = deepcopy(saved)
    result = canonical_roles(saved)
    assert saved == original
    assert result['agent_execution_order'] == ['I1', 'I2', 'I3']
    assert result['llm_role'] == 'grounded_I1_I2_I3_evidence_review'
    row = result['components'][0]
    assert row['i1']['agent']['task'] == 'I1'
    assert row['validation']['reasons'] == ['I3_agent_not_confirmed']
    assert row['component'] == saved['components'][0]['component']
    assert all(result[key] == saved[key] for key in ('input_sbom', 'gold', 'perturbation'))
    assert canonical_roles(result) == result


def test_conflicting_old_and_current_role_fields_are_rejected():
    from src.item3.agents.agent_role_labels import canonical_roles
    with pytest.raises(ValueError, match='Conflicting identification role fields'):
        canonical_roles({'c1': {'status': 'old'}, 'i1': {'status': 'current'}})
