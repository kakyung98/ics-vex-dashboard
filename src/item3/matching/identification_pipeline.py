"""Grounded local LLM agents by default, with an explicit deterministic baseline."""
from src.item3.evidence.product_identity_evidence import run_evidence
from src.item3.agents.evidence_review_agents import configured_mode
ARCHITECTURE='conditional-identification-agents-v2'
RULE_ARCHITECTURE='deterministic-identification-v1'


def infer_agent(task,payload):
    import json
    from pathlib import Path
    config=Path(__file__).resolve().parents[3]/'data/identification_runtime.json'
    if config.is_file() and json.loads(config.read_text(encoding='utf-8')).get('runtime')=='precision_shared_14b_v1':
        from src.common.runtime.shared_adapter_runtime import get_precision_runtime
        return get_precision_runtime().identification_agent(task,payload)
    from src.item3.agents.identification_model_runtime import get_runtime
    return get_runtime().identification_agent(task,payload)


def infer_i1(packet):
    return infer_agent('I1',packet)


# The service and file evaluator share this provider. Structured evidence alone
# must not silently turn an agents run into the deterministic baseline.
infer_agent.require_identity_review = True


def run_unified(sbom,nvd,*,index=None,agents=None,ranker=None,progress=None,mode=None,mapping_scope='configuration',component_cache=None):
    from src.common.data.sbom_input_normalization import to_analysis_input
    sbom=to_analysis_input(sbom)
    mode=mode or configured_mode()
    if mode not in {'agents','rules'}:raise ValueError('Use agents or rules identification mode.')
    provider=(agents or infer_agent) if mode=='agents' else None
    if mapping_scope not in ('configuration','identification'):raise ValueError('Unsupported CVE mapping scope')
    result=run_evidence(sbom,nvd,index=index,progress=progress,use_llm=False,identification_agents=provider,mapping_scope=mapping_scope,component_cache=component_cache)
    rows=result['components']
    used=any(bool((row.get(stage,{}).get('agent') or {}).get('llm_used')) for row in rows for stage in ('i1','i2','i3'))
    result.update(architecture=ARCHITECTURE if mode=='agents' else RULE_ARCHITECTURE,
                  llm_role='grounded_I1_I2_I3_evidence_review' if mode=='agents' else None,
                  llm_used=used,identification_mode=mode,
                  independent_accuracy_evaluated=False,i1_contract='source_preserving_agent_ranking' if mode=='agents' else 'source_preserving_rules',
                  i1_new_contract_fine_tuned=any(bool((r.get('i1',{}).get('agent') or {}).get('fine_tuned_for_role')) for r in rows),
                  trained_identity_roles=sorted({stage.upper() for r in rows for stage in ('i1','i2','i3') if (r.get(stage,{}).get('agent') or {}).get('fine_tuned_for_role')}),
                  legacy_identification_adapters_used=False)
    return result
