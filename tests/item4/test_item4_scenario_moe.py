from copy import deepcopy
import json

import pytest

from src.item4.models import scenario_review_experts as moe
from src.item4.decision import inventory_evidence_policy as current


def scenario(**context):
    return dict(id='case-1', cve='CVE-2099-1000', synthetic=True, answers={'q': 'o'},
                context=dict(dict(scope='current_single', deployment='running', runtime='bom',
                                  mode='normal', origin='same_zone'), **context))


def product(state='known_affected'):
    row = dict(evidence_id='p-1', product_key='supplier:p1', status=state,
               version_membership='true', source_version='1.2.3', document_sha256='a'*64,
               product_pointer='/products/0', status_pointer='/statuses/0', source_file='test.json')
    return dict(cve='CVE-2099-1000', component_ref='a1', version='1.2.3',
                state=state, evidence=[row], reasons=[])


def rule():
    return dict(expression={'condition': 'c'}, conditions=[dict(id='c', question_id='q',
                source_id='notice-1', quote='The optional service is enabled.', evidence_id='p-1')])


def panel(**overrides):
    calls = []
    def runner(prompt, packet, *, role):
        assert role == moe.INFERENCE_ROLE
        who = packet['expert']
        calls.append((prompt, deepcopy(packet)))
        data = packet['evidence']['e0']
        defaults = {'inventory': 'absent_complete' if data.get('deployment') == 'not_deployed'
                    else 'installed_exact', 'supplier': data.get('status'),
                    'conditions': 'satisfied', 'crosscheck': 'corroborated'}
        choice = overrides.get(who, defaults[who])
        if callable(choice):
            choice = choice()
        result = choice if isinstance(choice, dict) else dict(finding=choice, cite='e0')
        return dict(model='fixture', llm_used=True, prediction=result)
    return runner, calls


@pytest.mark.parametrize(('state','expected'), [('fixed','fixed'), ('known_not_affected','not_affected'),
                                              ('known_affected','under_investigation')])
def test_exact_supplier_and_deployment_only(state, expected):
    runner, calls = panel()
    candidate = moe.generate_candidate(scenario(), product(state), runner=runner)
    assert candidate['candidate_status'] == expected
    assert candidate['expert_validated'] is False
    assert candidate['generation_status'] == 'completed'
    assert candidate['routed_experts'] == ['supplier','inventory','crosscheck']
    assert len(set(prompt for prompt, _ in calls)) == 3
    assert not any(e['llm_used'] or e['model_called'] for e in candidate['experts'])
    assert candidate['cited_evidence']['p-1']['document_sha256'] == 'a'*64


def test_unsigned_or_scoped_mismatch_and_invalid_proofs_never_clear():
    runner, _ = panel()
    expected = 'under_investigation'
    for ctx in [dict(scope='mixed'), dict(runtime='mixed'), dict(runtime='bom_range'),
                dict(deployment='unknown')]:
        assert moe.generate_candidate(scenario(**ctx), product('fixed'), runner=runner)['candidate_status'] == expected
    for flag in ['unknown','conflicting']:
        p = product('fixed')
        p['state'] = flag
        assert moe.generate_candidate(scenario(), p, runner=runner)['candidate_status'] == expected
    p = product('fixed')
    p['evidence'][0]['version_membership'] = 'false'
    assert moe.generate_candidate(scenario(), p, runner=runner)['candidate_status'] == expected
    with pytest.raises(ValueError, match='scopes differ'):
        moe.generate_candidate(dict(scenario(), cve='CVE-2099-1001'), p, runner=runner)


def test_actual_inventory_absence_requires_complete_scoped_evidence():
    runner, _ = panel()
    obs = dict(scenario(deployment='not_deployed'), synthetic=False)
    assert moe.generate_candidate(obs, product(), runner=runner)['candidate_status'] == 'under_investigation'
    obs['context']['inventory_coverage'] = 'complete'
    assert moe.generate_candidate(obs, product(), runner=runner)['candidate_status'] == 'not_affected'
    obs['context']['scope'] = 'mixed'
    assert moe.generate_candidate(obs, product(), runner=runner)['candidate_status'] == 'under_investigation'
    assert moe.generate_candidate(scenario(deployment='not_deployed', inventory_coverage='partial'),
                                  product(), runner=runner)['candidate_status'] == 'under_investigation'


@pytest.mark.parametrize('synthetic', [True, False])
@pytest.mark.parametrize('field', [{}, {'inventory_coverage': 'partial'}, {'inventory_coverage': None},
                                   {'inventory_coverage': True}, {'inventory_coverage': 'unknown'},
                                   {'inventory_coverage': 'complete'}])
def test_explicit_inventory_policy_receipts_and_gate(synthetic, field):
    sample = dict(scenario(deployment='not_deployed', **field), synthetic=synthetic)
    runner, packets = panel()
    row = current.generate_candidate(sample, product(), runner=runner)
    complete = field.get('inventory_coverage') == 'complete'
    assert row['candidate_status'] == ('not_affected' if complete else 'under_investigation')
    assert row['reasons'] == ([] if complete else [current.MISSING_COMPLETENESS])
    assert row['inventory_observation']['field_present'] == ('inventory_coverage' in field)
    for _, packet in packets:
        if packet['expert'] in ('inventory', 'crosscheck'):
            assert packet['evidence']['e0']['complete_inventory'] is complete
    assert ('inventory_coverage' in sample['context']) == ('inventory_coverage' in field)


def test_explicit_policy_batch_matches_serial_and_does_not_reuse_assumed_absence():
    from src.item4.models import expert_batch_inference as old_batch
    sample = scenario(deployment='not_deployed')
    items = [(sample, product(), None)]
    runner, _ = panel()
    cache = {}
    def provider(requests):
        return [runner(req['system'], req['packet'], role=moe.INFERENCE_ROLE) for req in requests]
    old, = old_batch.generate_candidates(items, cache=cache, provider=provider)
    new, = current.generate_candidates(items, cache=cache, provider=provider)
    single = current.generate_candidate(sample, product(), runner=runner)
    assert old['candidate_status'] == 'not_affected'
    assert new['candidate_status'] == single['candidate_status'] == 'under_investigation'
    assert new['reasons'] == single['reasons'] == [current.MISSING_COMPLETENESS]
    assert new['input_sha256'] == single['input_sha256'] != old['input_sha256']
    assert new['version'] == current.VERSION
    assert new['experts'][0]['execution'] == 'cached'
    for index in [1, 2]:
        assert old['experts'][index]['wire_sha256'] != new['experts'][index]['wire_sha256']
        assert new['experts'][index]['model_called']


def test_explicit_completeness_does_not_override_other_required_evidence():
    case = scenario(deployment='not_deployed', inventory_coverage='complete')
    fixture = product()
    for ctx, ref, overrides in [('mixed', 'a1', {}), ('current_single', None, {}),
                                ('current_single', 'a1', {'inventory': 'unresolved'}),
                                ('current_single', 'a1', {'crosscheck': 'insufficient'})]:
        runner, _ = panel(**overrides)
        original = dict(case, context=dict(case['context'], scope=ctx))
        result = current.generate_candidate(original, dict(fixture, component_ref=ref), runner=runner)
        assert result['candidate_status'] == 'under_investigation'
    runner, _ = panel()
    assert current.generate_candidate(scenario(), product('known_not_affected'), runner=runner)['candidate_status'] == 'not_affected'


def test_condition_routing_and_trivalent_logic_gate():
    runner, _ = panel()
    data = scenario()
    source = rule()
    outcome = moe.generate_candidate(data, product(), condition_rule=source, runner=runner)
    assert outcome['candidate_status'] == 'affected' and 'conditions' in outcome['routed_experts']
    for value in ['x','unknown']:
        data['answers']['q'] = value
        assert moe.generate_candidate(data, product(), condition_rule=source, runner=runner)['candidate_status'] == 'under_investigation'
    data['answers']['q'] = 'x'
    source['expression'] = {'op':'not', 'args':[{'condition':'c'}]}
    assert moe.generate_candidate(data, product(), condition_rule=source, runner=runner)['candidate_status'] == 'affected'
    source['conditions'][0]['evidence_id'] = 'out-of-scope'
    assert 'invalid_condition_binding' in moe.generate_candidate(data, product(), condition_rule=source, runner=runner)['reasons']


def test_disagreement_invalid_citation_and_model_failure_are_visible():
    runner, _ = panel(crosscheck='insufficient')
    assert moe.generate_candidate(scenario(), product('fixed'), runner=runner)['candidate_status'] == 'under_investigation'
    runner, _ = panel(supplier={'finding':'fixed','cite':'missing'})
    result = moe.generate_candidate(scenario(), product('fixed'), runner=runner)
    assert result['candidate_status'] == 'under_investigation' and result['generation_status'] == 'partial'
    def offline(*args, **kwargs):
        raise OSError('unavailable')
    result = moe.generate_candidate(scenario(), product(), runner=offline)
    assert result['generation_status'] == 'failed' and all(e['execution']=='error' for e in result['experts'])


def test_cache_provenance_and_no_label_leakage_across_repeated_scenarios():
    runner, calls = panel()
    cache = {}
    obs = dict(scenario(), id='SECRET_LABEL', actual_affected='SECRET_GOLD', prediction='SECRET_PRED')
    p = dict(product(), arbitrary_debug_field='SECRET_DEBUG')
    first = moe.generate_candidate(obs, p, runner=runner, cache=cache)
    second = moe.generate_candidate(dict(obs,id='another'), p, runner=runner, cache=cache)
    assert first['input_sha256'] == second['input_sha256'] and len(calls)==3
    assert all(e['execution']=='cached' and not e['model_requested'] for e in second['experts'])
    assert 'SECRET' not in json.dumps(calls)
    distinct = moe.generate_candidate(scenario(scope='mixed'), p, runner=runner, cache=cache)
    assert distinct['input_sha256'] != first['input_sha256'] and len(calls)==5


@pytest.mark.parametrize(('choice','verdict','cited'), [
    ('conflicting_group0', 'conflicting', ['p-1','p-2']), ('unresolved', 'unresolved', [])])
def test_verified_conflict_choice_binds_each_cited_in_range_row(choice, verdict, cited):
    source = product()
    source['state'] = 'conflicting'
    source['evidence'].extend([
        dict(source['evidence'][0], evidence_id='p-2', status='known_not_affected'),
        dict(source['evidence'][0], evidence_id='out', status='fixed', version_membership='false')])
    run, calls = panel(supplier={'assessment': choice})
    result = moe.generate_candidate(scenario(), source, runner=run)
    receipt = result['experts'][0]
    assert result['generation_status'] == 'completed' and result['candidate_status'] == moe.UNKNOWN
    assert receipt['offered_conflict_group']['evidence_ids'] == ['p-1','p-2']
    assert receipt['verdict'] == verdict and receipt['evidence_ids'] == cited
    assert calls[0][1]['citation_groups'] == {'group0':['e0','e1']}
    assert all(result['cited_evidence'][eid]['version_membership']=='true' for eid in cited)


def test_missing_or_fabricated_conflict_citations_are_rejected_and_retried():
    run, calls = panel(supplier={'finding':'conflicting','cite':'e0'})
    source = product('fixed')
    # A different status outside this build cannot establish an in-scope contradiction.
    source['evidence'].append(dict(source['evidence'][0], evidence_id='out', status='known_affected',
                                   version_membership='unknown'))
    cache = {}
    for _ in range(2):
        result = moe.generate_candidate(scenario(), source, runner=run, cache=cache)
        failure = result['experts'][0]
        assert result['generation_status'] == 'partial' and result['candidate_status'] == moe.UNKNOWN
        assert (failure['error_kind'], failure['reason_code']) == ('evidence','no_verified_conflict_pair')
        assert failure['execution'] == 'error' and not failure['evidence_ids']
    assert len([p for _, p in calls if p['expert']=='supplier']) == 2
    source['state'] = 'conflicting'
    source['evidence'][1]['version_membership'] = 'true'
    bad, _ = panel(supplier={'assessment':'some_other_group'})
    failure = moe.generate_candidate(scenario(), source, runner=bad)['experts'][0]
    assert (failure['error_kind'],failure['reason_code']) == ('output_contract','invalid_conflict_choice')
    def offline(*args, **kwargs):
        raise OSError()
    result = moe.generate_candidate(scenario(), source, runner=offline)
    assert all(e['reason_code']=='provider_exception' for e in result['experts'])
