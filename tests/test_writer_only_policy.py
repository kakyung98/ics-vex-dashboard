import pytest
from src.inference_policy import require_writer
from src.identification_agents import LocalIdentificationAgents
from src import vex_roles as VR,operational_questions as OQ
from src.candidate_match import match_candidates
from src.identity_evidence import run_evidence
from tests.test_identity_evidence import index,sbom


@pytest.mark.parametrize('role',['L2','L3','L4','l2-candidates','condition-evidence','item4-questions','operation-assessment','research-question-review','research-source-map'])
def test_every_analysis_role_rejected_before_gpu_loading(role):
    runtime=LocalIdentificationAgents()
    with pytest.raises(ValueError,match='disabled outside final VEX'):
        runtime.grounded_role(role,{})
    assert runtime.model is None
    require_writer('vex-writer')


@pytest.mark.parametrize('mode',['unified','rules','base','tuned','evidence','evidence_llm'])
def test_legacy_identification_selectors_cannot_reenable_models(monkeypatch,mode):
    import src.unified_identification as unified
    from ics_agent_matcher_full.ics_agent_matcher.matcher import NVD
    def forbidden(*args,**kwargs):raise AssertionError('No analysis LLM')
    monkeypatch.setattr(VR,'infer',forbidden)
    monkeypatch.setattr(unified,'get_agents',forbidden,raising=False)
    monkeypatch.setattr('src.identity_evidence.get_index',index)
    result=match_candidates(sbom(),agent_mode=mode,lookup_mode='none',nvd=NVD(offline=True))
    assert result['agent_mode']=='deterministic' and result['llm_used'] is False
    assert result['components'][0]['validation']['product']=='curl'


def test_rule_questions_and_answers_invoke_only_the_final_writer(monkeypatch):
    calls=[]
    def writer(role,packet):
        assert role=='vex-writer';calls.append(role)
        return {'prediction':{'vulnerability':packet['vulnerability'],'product':packet['product'],
            'status':packet['decision']['status'],'justification':packet['decision']['justification'],
            'impact_statement':packet['evidence'][0]['text'],'evidence_refs':[packet['evidence'][0]['id']],
            'action_statement':None}}
    monkeypatch.setattr(VR,'infer',writer)
    plan=OQ.create([{'cve':'CVE-2099-12345','description':'The device transmits unencrypted network traffic.'}],
                   'Device','writer-only-test',question_role='item4-questions')
    assert not calls
    assert plan['cases'][0]['generation']['llm_used'] is False
    result=OQ.assess(plan['id'],{})
    assert calls==['vex-writer']
    statement=result['statements'][0]
    assert statement['status']=='under_investigation'
    assert statement['authoring']['status']=='validated_draft'
    assert statement['extraction']['llm_used'] is False
    assert statement['operational_review']['assessment']['llm_used'] is False
