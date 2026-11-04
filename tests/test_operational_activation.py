from src import operational_model_config as config,operational_questions as OQ,vex_roles as VR
from tests.test_operational_questions import create

def test_operational_adapter_activation_is_disabled_even_with_old_environment(monkeypatch):
    monkeypatch.setenv('ICSVEX_OPERATIONAL_MODEL_MODE','tuned')
    assert config.configured('item4-questions') is None
    assert config.configured('operation-assessment') is None
    assert all(r['configured_mode']=='rules' for r in config.status()['roles'])

def test_operational_pipeline_uses_only_final_writer(monkeypatch):
    calls=[]
    def only_writer(role,packet):
        assert role=='vex-writer';calls.append(role)
        return {'prediction':None,'error':'test_writer_unavailable'}
    monkeypatch.setattr(VR,'infer',only_writer)
    monkeypatch.setattr(VR,'infer_base',lambda *a: (_ for _ in ()).throw(AssertionError('No base fallback')))
    plan=create();assert not calls
    result=OQ.assess(plan['id'],{})
    assert calls==['vex-writer']
    assert result['statements'][0]['status']=='under_investigation'
    assert result['statements'][0]['operational_review']['assessment']['llm_used'] is False

def test_self_review_environment_does_not_invoke_a_model(monkeypatch):
    monkeypatch.setenv('ICSVEX_QUESTION_SELF_REVIEW','1')
    monkeypatch.setattr(VR,'infer',lambda *a: (_ for _ in ()).throw(AssertionError('Question model must not run')))
    monkeypatch.setattr(VR,'infer_base',lambda *a: (_ for _ in ()).throw(AssertionError('Critic must not run')))
    plan=create()
    assert plan['cases'][0]['generation']['llm_used'] is False
