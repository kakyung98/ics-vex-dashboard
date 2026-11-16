"""Explicit inference roles; identification uses separately validated contracts."""
ALLOWED_ROLE='vex-writer'
ALLOWED_INFERENCE_ROLES={'vex-writer','item4-questions','identity-L2','identity-L3','identity-L4'}


def require_inference_role(role):
    if role not in ALLOWED_INFERENCE_ROLES:
        raise ValueError('LLM inference is disabled outside final VEX authoring, CVE questions and grounded identification roles: '+str(role))


def require_writer(role):
    if role!=ALLOWED_ROLE:
        raise ValueError('LLM inference is disabled outside final VEX authoring: '+str(role))
