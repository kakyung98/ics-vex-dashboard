"""Grounded local LLM agents by default, with an explicit deterministic baseline."""
from src.identity_evidence import run_evidence
from src.identification_agent_flow import configured_mode
ARCHITECTURE='conditional-identification-agents-v2'
RULE_ARCHITECTURE='deterministic-identification-v1'


def infer_agent(task,payload):
    from src.identification_agents import get_runtime
    return get_runtime().identification_agent(task,payload)


def infer_l2(packet):
    return infer_agent('L2',packet)


def run_unified(sbom,nvd,*,index=None,agents=None,ranker=None,progress=None,mode=None,mapping_scope='configuration'):
    from src.project_input_contract import to_analysis_input
    sbom=to_analysis_input(sbom)
    mode=mode or configured_mode()
    if mode not in {'agents','rules'}:raise ValueError('Use agents or rules identification mode.')
    provider=(agents or infer_agent) if mode=='agents' else None
    if mapping_scope not in ('configuration','identification'):raise ValueError('Unsupported CVE mapping scope')
    result=run_evidence(sbom,nvd,index=index,progress=progress,use_llm=False,identification_agents=provider,mapping_scope=mapping_scope)
    rows=result['components']
    used=any(bool((row.get(stage,{}).get('agent') or {}).get('llm_used')) for row in rows for stage in ('l2','l3','l4'))
    result.update(architecture=ARCHITECTURE if mode=='agents' else RULE_ARCHITECTURE,
                  llm_role='grounded_L2_L3_L4_evidence_review' if mode=='agents' else None,
                  llm_used=used,identification_mode=mode,
                  independent_accuracy_evaluated=False,l2_contract='source_preserving_agent_ranking' if mode=='agents' else 'source_preserving_rules',
                  l2_new_contract_fine_tuned=any(bool((r.get('l2',{}).get('agent') or {}).get('fine_tuned_for_role')) for r in rows),
                  trained_identity_roles=sorted({stage.upper() for r in rows for stage in ('l2','l3','l4') if (r.get(stage,{}).get('agent') or {}).get('fine_tuned_for_role')}),
                  legacy_identification_adapters_used=False)
    return result
