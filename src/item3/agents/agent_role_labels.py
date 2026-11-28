"""Read historical identification results using the current public role names."""
import re

_OLD = re.compile(r'^(identity-)?([LlPp])([234])(?=$|_|-|\s|·)')
# Read-only compatibility for results written before the I-role naming revision.
_PREVIOUS = re.compile(r'^(identity-)?([Cc])([123])(?=$|_|-|\s|·)')
_ROLE_FIELDS = {'task', 'role', 'axis', 'stage', 'agent_execution_order', 'completed',
                'trained_roles', 'runtime_roles', 'shared_tasks', 'trained_identity_roles',
                'selected_agents', 'executed_agents', 'blocked_agents', 'skipped_agents',
                'label', 'title', 'trace', 'agent_trace', 'execution_order', 'selected_roles'}
_SOURCE_FIELDS = {'input_sbom', 'sbom', 'bom', 'component', 'evidence', 'gold',
                  'perturbation', 'source_condition', 'original_prediction', 'raw'}
_ROLE_TEXT_FIELDS = {'identity_notice', 'method', 'missing_evidence', 'model_status',
                     'reasons', 'reason', 'acceptance_rule', 'scope', 'architecture',
                     'llm_role', 'i1_contract'}


def _name(value):
    value = _OLD.sub(lambda m: (m[1] or '') + ('I' if m[2].isupper() else 'i') + str(int(m[3]) - 1), value)
    return _PREVIOUS.sub(lambda m: (m[1] or '') + ('I' if m[2].isupper() else 'i') + m[3], value)


def _role_text(value):
    value = re.sub(r'(?<![A-Za-z0-9])([LP])([234])(?=$|[^A-Za-z0-9])',
                   lambda m: 'I' + str(int(m[2]) - 1), value)
    return re.sub(r'(?<![A-Za-z0-9])([Cc])([123])(?=$|[^A-Za-z0-9])',
                  lambda m: ('I' if m[1].isupper() else 'i') + m[2], value)


def canonical_roles(value, field=''):
    """Return a copy; leave source evidence, product values and stored history intact."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            current = _name(key)
            converted = canonical_roles(item, current) if key not in _SOURCE_FIELDS else item
            if current in result and result[current] != converted:
                raise ValueError('Conflicting identification role fields: ' + current)
            result[current] = converted
        return result
    if isinstance(value, list):
        return [canonical_roles(item, field) for item in value]
    if isinstance(value, str):
        if field in _ROLE_FIELDS:
            return _name(value)
        if field in _ROLE_TEXT_FIELDS:
            return _role_text(value)
    return value
