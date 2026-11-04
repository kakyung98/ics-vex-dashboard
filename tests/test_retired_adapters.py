import pytest
from fastapi.testclient import TestClient
from src.identification_agents import LocalIdentificationAgents
from src.api_server import app


def test_retired_free_quote_loader_rejects_before_loading_gpu_or_weights():
    runtime=LocalIdentificationAgents()
    with pytest.raises(ValueError,match='disabled outside'):
        runtime.grounded_role('cve-conditions',{})
    assert runtime.model is None


def test_model_status_does_not_advertise_retired_adapter():
    data=TestClient(app).get('/api/vex-review/models').json()
    assert [r['role'] for r in data['roles']]==['vex-writer']
    assert {r['role'] for r in data['operational_models']['roles']}=={'item4-questions','operation-assessment'}
