"""Explicit inference roles; identification uses separately validated contracts."""
ALLOWED_ROLE='vex-writer'
ALLOWED_INFERENCE_ROLES={'vex-writer','item4-questions','identity-I1','identity-I2','identity-I3',
                         'exploitation-prerequisites','exploitation-coverage-review','operating-record-review'}


def require_inference_role(role):
    if role not in ALLOWED_INFERENCE_ROLES:
        raise ValueError('LLM inference role is not enabled: '+str(role))


def require_writer(role):
    if role!=ALLOWED_ROLE:
        raise ValueError('LLM inference is disabled outside final VEX authoring: '+str(role))
