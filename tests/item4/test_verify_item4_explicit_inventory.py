from copy import deepcopy
import hashlib
import json

import pytest

from tools.item4.verify_item4_explicit_inventory import HOLD, VERSION, check_revision


def example():
    context = {'scope': 'current_single', 'deployment': 'not_deployed'}
    prior = dict(id='original-case', version='original-version', run_id='historical', input_sha256='original-input',
                 candidate_status='not_affected', reasons=[], synthetic=True, expert_validated=False,
                 verified_product={'component_ref': 'component-1'}, experts=[{'expert': 'inventory'}],
                 routed_experts=['inventory'], evidence_ids=['legacy'], cited_evidence={'legacy': 'historical'},
                 source_rule_identities=None, inference_role='historical-role')
    sha = hashlib.sha256(json.dumps([VERSION, 'row-hash', 'input-hash'], separators=(',', ':')).encode()).hexdigest()
    fields = dict(prior, version=VERSION, run_id='revision', input_sha256=sha, candidate_status='under_investigation',
                  reasons=[HOLD], experts=[], routed_experts=[], evidence_ids=[], cited_evidence={}, inference_role=None,
                  inventory_review=dict(source_input_sha256='input-hash', scope='current_single',
                                        deployment='not_deployed', inventory_coverage_present=False, inventory_coverage=None,
                                        component_ref='component-1', decision='coverage_required'),
                  source_decision=dict(run_id='historical', version='original-version', input_sha256='original-input',
                                       row_sha256='row-hash'))
    return fields, prior, 'row-hash', 'input-hash', context, True, 'revision'


@pytest.mark.parametrize('changes', [
    {'candidate_status': 'not_affected'}, {'reasons': ['crosscheck_did_not_corroborate']},
    {'cited_evidence': {'legacy': 'historical'}},
    {'experts': [{'expert': 'inventory', 'model_called': True, 'model_requested': True}]},
    {'input_sha256': 'original-input'},
])
def test_rejects_stale_claims_in_a_reclassified_absence(changes):
    row, *arguments = example()
    assert check_revision(row, *arguments) == 0
    row.update(changes)
    with pytest.raises(ValueError):
        check_revision(row, *arguments)


def test_missing_coverage_requires_an_explicit_missing_field_record():
    row, *arguments = example()
    revised = deepcopy(row)
    revised['inventory_review']['inventory_coverage'] = 'complete'
    with pytest.raises(ValueError, match='inventory_review'):
        check_revision(revised, *arguments)
