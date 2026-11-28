from copy import deepcopy

import pytest

from src.item4.evaluation import supplier_evidence_review as contract
from tools.item4.verify_item4_supplier_pilot import check_supplier, scope_sha


def supplier_case(eligibility, statuses, choice, verdict, citations):
    rows = [(f'proof-{index}', dict(product_key='p', source_version='1.0', status=status, version_membership=inside))
            for index, (inside, status) in enumerate(zip(eligibility, statuses))]
    request = contract.build_request(rows)
    wire = contract.wire_sha256(request)
    model = dict(model='test-serial', provider='local_shared_base')
    source = dict(wire_sha256='old-wire', input_sha256='old-scoped-input')
    expert = dict(wire_sha256=wire, v2_wire_sha256=source['wire_sha256'], v2_scope_sha256=source['input_sha256'],
                  input_sha256=scope_sha([contract.VERSION, wire, [eid for eid, _ in rows]]),
                  response_source='pilot_supplier_model', model=model, execution='model', model_called=True,
                  selection=choice, llm_used=True, contract_version=contract.VERSION, verdict=verdict,
                  evidence_ids=citations)
    return source, expert, rows, request, dict(model=model, prediction={'assessment': choice})


def test_uncertain_version_cannot_be_the_citation_even_for_the_same_published_status():
    sample = supplier_case(['unknown', 'true'], ['known_affected'] * 2, 'support_e1', 'known_affected', ['proof-1'])
    check_supplier(*sample)
    source, expert, rows, request, output = deepcopy(sample)
    expert['evidence_ids'] = ['proof-0']
    with pytest.raises(ValueError, match='citations'):
        check_supplier(source, expert, rows, request, output)


def test_true_conflict_must_cite_both_applicable_statuses():
    sample = supplier_case(['true', 'unknown', 'true'], ['fixed', 'known_affected', 'known_affected'],
                           'conflicting_group0', 'conflicting', ['proof-0', 'proof-2'])
    check_supplier(*sample)
    source, expert, rows, request, output = deepcopy(sample)
    expert['evidence_ids'] = ['proof-0', 'proof-1']
    with pytest.raises(ValueError, match='citations'):
        check_supplier(source, expert, rows, request, output)


def test_reused_output_cannot_be_marked_as_a_fresh_call():
    sample = supplier_case(['false'], ['known_affected'], 'unresolved', 'unresolved', [])
    source, expert, rows, request, output = sample
    expert['execution'] = 'cached'
    with pytest.raises(ValueError, match='execution'):
        check_supplier(source, expert, rows, request, output)
    expert['model_called'] = False
    check_supplier(*sample)
