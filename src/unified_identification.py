"""Deterministic identification; model inference is reserved for final VEX writing."""
from src.identity_evidence import run_evidence
ARCHITECTURE='deterministic-identification-v1'
def infer_agent(task,payload):
    raise ValueError('Model-based identification is disabled.')
def infer_l2(packet):
    raise ValueError('Model-based ranking is disabled.')
def run_unified(sbom,nvd,*,index=None,agents=None,ranker=None,progress=None):
    result=run_evidence(sbom,nvd,index=index,progress=progress,use_llm=False)
    result.update(architecture=ARCHITECTURE,llm_role=None,llm_used=False,
                  independent_accuracy_evaluated=False,l2_contract='source_preserving_rules',
                  l2_new_contract_fine_tuned=False)
    return result
