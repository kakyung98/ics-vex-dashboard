import hashlib
import json

import pytest

from src.item4.models import scenario_review_experts as v2
from src.item4.evaluation import supplier_evidence_review as review


def supplier(eid, membership, status='known_affected', source_version='before 3.0'):
    return eid, dict(product_key='공급사:controller', source_version=source_version,
                     status=status, version_membership=membership)


def options(rows):
    return review.build_request(rows)['packet']['schema']['properties']['assessment']['enum']


@pytest.mark.parametrize('status', v2.SUPPLIER_STATES)
def test_one_bound_status_and_optional_abstention(status):
    rows = [supplier('ambiguous', 'unknown', status), supplier('in-range', 'true', status),
            supplier('out-of-range', 'false', 'fixed')]
    assert options(rows) == ['support_e1', 'unresolved']
    assert review.resolve(rows, {'assessment': 'support_e1'}) == {'finding': status, 'cite': 'e1'}
    assert review.resolve(rows, {'assessment': 'unresolved'}) == {'finding': 'unresolved', 'cite': 'none'}


@pytest.mark.parametrize('rows', [[], [supplier('ambiguous', 'unknown', source_version='')],
                                  [supplier('out', 'false'), supplier('ambiguous', 'unknown', 'fixed')]])
def test_no_confirmed_membership_offers_only_abstention(rows):
    assert options(rows) == ['unresolved']
    with pytest.raises(ValueError):
        review.resolve(rows, None)
    with pytest.raises(ValueError):
        review.resolve(rows, {'assessment': 'support_e0'})


def test_true_conflict_payload_and_citations_match_original_v2():
    rows = [supplier('out', 'false', 'fixed'), supplier('a', 'true'), supplier('b', 'true', 'fixed'),
            supplier('c', 'true'), supplier('possible', 'unknown', 'known_not_affected')]
    req = review.build_request(rows)
    assert req['packet']['citation_groups'] == {'group0': ['e1', 'e2']}
    assert options(rows) == ['conflicting_group0', 'unresolved']
    for choice, expected in [('conflicting_group0', ['a', 'b']), ('unresolved', [])]:
        prediction = review.resolve(rows, {'assessment': choice})
        def runner(system, packet, *, role):
            assert role == v2.INFERENCE_ROLE
            assert system == req['system']
            assert json.dumps(packet, ensure_ascii=False) == json.dumps(req['packet'], ensure_ascii=False)
            return {'model': 'fixture', 'llm_used': True, 'prediction': prediction}
        receipt = v2._expert('supplier', rows, runner, None)
        assert receipt['evidence_ids'] == expected
        assert receipt['verdict'] == ('conflicting' if expected else 'unresolved')
    with pytest.raises(ValueError):
        review.resolve(rows, {'assessment': 'support_e1'})
    same_status = [supplier('a', 'true'), supplier('b', 'true')]
    assert options(same_status) == ['support_e0', 'unresolved']


@pytest.mark.parametrize('bad', [
    {'finding': 'conflicting', 'cite': 'e0'}, {'assessment': 'conflicting_group0'},
    {'assessment': 'support_e0'}, {'assessment': 'support_e2'}, {'assessment': 'support_e9'},
    {'assessment': 'support_e1', 'cite': 'e0'}, {'assessment': ['support_e1']}, None])
def test_rejects_unbound_choices_and_malformed_response(bad):
    rows = [supplier('unresolved', 'unknown'), supplier('verified', 'true'), supplier('other', 'false')]
    with pytest.raises(ValueError):
        review.resolve(rows, bad)


@pytest.mark.parametrize('bad', [
    {'product_key': ''}, {'source_version': None}, {'source_version': '', 'version_membership': 'true'},
    {'version_membership': True}, {'version_membership': 'possible'}, {'status': 'resolved'},
    {'status': 'unresolved'}, {'unexpected_label': 'fixed'}])
def test_rejects_unverified_or_unexpected_evidence_fields(bad):
    eid, original = supplier('record', 'unknown')
    with pytest.raises(ValueError):
        review.build_request([(eid, {**original, **bad})])


def test_rejects_invalid_and_duplicate_evidence_ids():
    eid, original = supplier('record', 'unknown')
    with pytest.raises(ValueError):
        review.build_request([(eid, original), (eid, original)])
    with pytest.raises(ValueError):
        review.build_request([('', original)])


def test_fingerprint_binds_exact_messages_and_scopes_citations_afterward():
    _, original = supplier('first', 'true')
    req = review.build_request([('local-id-1', original)])
    same = review.build_request([('different-local-id', original)])
    swapped = review.build_request([('local-id-1', dict(reversed(original.items())))])
    serialized = json.dumps([req['system'], json.dumps(req['packet'], ensure_ascii=False)],
                            ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assert review.wire_sha256(req) == hashlib.sha256(serialized).hexdigest()
    assert review.wire_sha256(req) == review.wire_sha256(same)
    assert review.wire_sha256(req) != review.wire_sha256(swapped)
    assert review.wire_sha256(req) != review.wire_sha256(dict(req, system=req['system']+'!'))


def test_supported_row_and_unknown_product_never_clear_an_installed_asset():
    rows = [supplier('unknown-matching-qualifier', 'unknown', 'fixed'), supplier('in-range', 'true', 'fixed')]
    product = dict(cve='CVE-2099-1111', component_ref='device', version='1.2', state='unknown',
                   evidence=[dict(row, evidence_id=eid) for eid,row in rows],
                   reasons=['unresolved_version_or_product_qualifier'])
    scenario = dict(id='scenario', cve=product['cve'], answers={}, synthetic=True,
                    context=dict(scope='current_single', deployment='running', runtime='bom'))
    def panel(system, packet, *, role):
        prediction = {
            'supplier': review.resolve(rows, {'assessment': 'support_e1'}),
            'inventory': {'finding': 'installed_exact', 'cite': 'e0'},
            'crosscheck': {'finding': 'corroborated', 'cite': 'e0'},
        }[packet['expert']]
        return {'model': 'fixture', 'llm_used': True, 'prediction': prediction}
    candidate = v2.generate_candidate(scenario, product, runner=panel)
    assert candidate['generation_status'] == 'completed'
    assert candidate['candidate_status'] == 'under_investigation'
    assert candidate['reasons'] == ['supplier_evidence_conflicting_or_unresolved']
    assert candidate['experts'][0]['evidence_ids'] == ['in-range']
