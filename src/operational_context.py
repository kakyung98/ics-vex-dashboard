"""Scoped operator reports support advisory estimates, never code clearance."""
import re


def validate(value, assets):
    value = value or {}
    allowed = {'deployment', 'scope', 'network_access', 'local_access', 'controls_enforced',
               'evidence', 'attested', 'covers_all_interfaces', 'component_refs',
               'deployment_known','scope_known','record_available','facts_checked','coverage_confirmed'}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError('Invalid operational context fields.')
    out = {}
    for key, limit in [('deployment', 2000), ('scope', 1000), ('evidence', 1500)]:
        text = value.get(key, '')
        if not isinstance(text, str) or len(text) > limit:
            raise ValueError('Invalid operational context text: ' + key)
        out[key] = text.strip()
    for key in ('network_access', 'local_access', 'controls_enforced'):
        out[key] = value.get(key, 'unknown')
        if out[key] not in {'yes', 'no', 'unknown'}:
            raise ValueError('Use yes, no or unknown for ' + key)
    for key in ('deployment_known','scope_known','record_available','facts_checked','coverage_confirmed'):
        out[key]=value.get(key,'unknown')
        if out[key] not in {'yes','no','unknown'}:raise ValueError('Use yes, no or unknown for '+key)
    for key in ('attested', 'covers_all_interfaces'):
        out[key] = value.get(key, False)
        if type(out[key]) is not bool:
            raise ValueError('Invalid context confirmation: ' + key)
    refs = value.get('component_refs', [])
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs) or set(refs) - {a['ref'] for a in assets}:
        raise ValueError('Unknown component reference in operational context.')
    out['component_refs'] = sorted(set(refs))
    out['provenance'] = 'operator_report'
    out['independently_verified'] = False
    return out


def estimate(case, context, evaluation, base):
    prediction = dict(base['prediction'])
    missing = list(prediction['missing_evidence'])
    refs = {str(m.get('component_id') or 'asset') for m in case.get('mappings', [])} or set(context['component_refs'])
    scoped = bool(refs) and refs <= set(context['component_refs']) and (context['covers_all_interfaces'] or context.get('coverage_confirmed')=='yes')
    recorded = bool(scoped and ((context['attested'] and context['scope'] and context['evidence']) or
        all(context.get(k)=='yes' for k in ('scope_known','record_available','facts_checked'))))
    vector = case.get('vector') or ''
    match = re.search(r'(?:^|/)AV:([NALP])(?:/|$)', vector)
    access = context['network_access'] if match and match[1] == 'N' else context['local_access'] if match and match[1] == 'L' else 'unknown'
    explanation = 'The supplied context does not yet support a scoped CVE estimate.'
    if not recorded:
        missing.append('Confirmed component/interface scope and an attested supporting operational record')
    elif access == 'no' and context['controls_enforced'] == 'yes':
        prediction['assessment'] = 'likely_mitigated'
        explanation = ('The operator reports enforced controls blocking the CVSS-described attack access path within the confirmed scope. '
                       'This is a mitigation hypothesis, not proof of code absence or safe deployment.')
        prediction['answer_refs'] = ['context:access', 'context:controls_enforced', 'context:evidence']
    elif access == 'yes' and evaluation['version_decided'] and any(r['state'] == 'listed_affected' for r in evaluation['components']) and all(
            r['state'] == 'listed_affected' for r in evaluation['components'] if r['state'] != 'not_selected'):
        prediction['assessment'] = 'likely_affected'
        explanation = ('An attested vendor-listed affected build and operator-reported attack access path are present. '
                       'The asset is potentially affected; actual triggers and exploitation remain unverified.')
        prediction['answer_refs'] = ['context:access', 'context:evidence']
    elif access == 'yes':
        missing.append('Confirmed installed-version applicability and CVE trigger conditions')
        explanation = 'The reported attack access path is present, but exposure alone does not establish CVE applicability or exploitability.'
    else:
        missing.append('CVE attack-vector evidence and a known scoped access-path answer')
    prediction.update(explanation=explanation, missing_evidence=list(dict.fromkeys(missing)))
    return {'prediction': prediction, 'method': 'scoped_operational_context_rules_v1', 'llm_used': False,
            'standard_vex_authority': False, 'independent_accuracy_evaluated': False}
