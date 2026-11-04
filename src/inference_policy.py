"""Application invariant: model inference is reserved for final VEX authoring."""
ALLOWED_ROLE='vex-writer'


def require_writer(role):
    if role!=ALLOWED_ROLE:
        raise ValueError('LLM inference is disabled outside final VEX authoring: '+str(role))
