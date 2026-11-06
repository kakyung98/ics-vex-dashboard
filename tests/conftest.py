"""Unit/API tests never allocate a real GPU; the standalone smoke runs do."""
import pytest
from src import vex_roles


@pytest.fixture(autouse=True)
def isolated_grounded_models(monkeypatch,tmp_path):
    # Historical free-quotation fixtures explicitly retain their comparison contract.
    # Source-ID default behavior is exercised separately with the environment overridden.
    monkeypatch.setenv('ICSVEX_EXTRACTION_STRATEGY','legacy_quotes')
    monkeypatch.setenv('ICSVEX_QUESTION_SELF_REVIEW','0')
    from src import review_store
    from src import gpu_lease
    monkeypatch.setattr(gpu_lease,'FILE',tmp_path/'unit-test-gpu-lease.json')
    from src import unified_identification
    monkeypatch.setattr(unified_identification,'infer_agent',lambda task,packet: {'prediction':None,'error':'unit_test_provider_unavailable'})
    monkeypatch.setattr(review_store,'DB',tmp_path/'sessions.sqlite3')
    monkeypatch.setattr(vex_roles,'infer',lambda role,packet: {'prediction':None,'raw':'','error':'unit_test_provider_unavailable','role':role})
    monkeypatch.setattr(vex_roles,'infer_base',lambda role,packet: {'prediction':None,'raw':'','error':'unit_test_base_provider_unavailable','role':role,'model_mode':'base'})
    with vex_roles._lock:vex_roles._cache.clear()


@pytest.fixture
def synthetic_evidence_routes(monkeypatch):
    """Execution-contract fixture only; never a CWE classification/gold label.

    Tests explicitly supply _fixture_requirement/_fixture_operating. Production
    ignores these fields. This preserves branch isolation/writer/export checks
    while no production evidence-routing criteria are assigned.
    """
    from src import item4_review
    from src.vex_routing import classify,workflow
    def fixture_route(case,*,source_available=False,**kwargs):
        row=classify(case,source_available=source_available)
        if '_fixture_requirement' not in case:
            return row
        return workflow({**row,'requirement':case['_fixture_requirement'],
                         'operational_required':case.get('_fixture_operating',False)},
                        source_available=source_available)
    monkeypatch.setattr(item4_review,'classify',fixture_route)
    return fixture_route
