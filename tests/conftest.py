"""Explicit inference boundaries for deterministic decision-policy tests."""
from copy import deepcopy

import pytest


@pytest.fixture(autouse=True)
def offline_cve_reference_collection(monkeypatch):
    """Unit tests pin source fixtures; live reference retrieval is checked separately."""
    monkeypatch.setenv('ICSVEX_REFERENCE_NETWORK','0')


@pytest.fixture
def supplier_rule_fixture(monkeypatch):
    """Stable source-linked inputs for policy/export and actual MulVAL tests.

    Generative extraction has separate contract tests and a live smoke check.
    Production still requires VEP; this fixture never enters its model cache.
    """
    from src.item4.analysis import exploitation_prerequisites as V

    def rule(original, registry):
        result = deepcopy(original)
        gaps = result.pop('unresolved_operands', [])
        result['implicit_values'] = {g['id']: 'unknown' for g in gaps}
        if gaps:
            result['expression'] = dict(op='and', args=[result['expression']] +
                                        [dict(condition=g['id']) for g in gaps])
        result['compiled_gaps'] = gaps
        result['coverage_complete'] = not bool(gaps)
        result['extraction_provider'] = 'explicit_test_supplier_predicates'
        return result

    monkeypatch.setattr(V, 'vendor_rule', rule)
