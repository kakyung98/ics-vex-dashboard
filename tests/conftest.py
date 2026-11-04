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
