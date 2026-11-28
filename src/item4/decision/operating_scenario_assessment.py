"""Source-free ICS observations bound to reviewed, CVE-specific scenarios.

This is the project extension to Vulntology, not a replacement native schema.
ATT&CK asset membership and MulVAL reachability cannot create CVE prerequisites.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from xml.etree import ElementTree as ET

from src.item4.decision.condition_logic_evaluation import logic; from src.item4.decision.condition_logic_evaluation import leaves
from src.item4.decision.evidence_review_gate import instant

SCOPE = ('cve', 'asset_ref', 'product', 'build', 'config_baseline', 'mode', 'actor_origin')
OVAL_NS = 'http://oval.mitre.org/XMLSchema/oval-results-5'
STATES = {'true', 'false', 'unknown'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def valid_evidence(item, binding, at):
    if not isinstance(item, dict): return False
    times = [instant(item.get(k)) for k in ('observed_at', 'valid_until')]
    return bool(all(isinstance(item.get(k), str) and item[k].strip() for k in ('source','quote','reviewer'))
        and all(item.get('binding', {}).get(k) == binding.get(k) for k in SCOPE)
        and None not in times and times[0] <= at <= times[1]
        and item.get('integrity_verified') is True)


def assess(packet, evaluated_at=None):
    """Evaluate only reviewed sufficient scenarios with fresh bound observations."""
    binding = packet.get('binding', {})
    at = instant(evaluated_at) if evaluated_at else datetime.now(timezone.utc)
    result = dict(binding=deepcopy(binding), status='under_investigation', condition_values={},
        scenario_results=[], missing_evidence=[], policy='ics-operational-context/1',
        synthetic=packet.get('synthetic') is True, source_code_required=False,
        tool_results=deepcopy(packet.get('tool_results', {})))
    if at is None or any(not isinstance(binding.get(k), str) or not binding[k].strip() for k in SCOPE):
        result['missing_evidence'].append('complete asset/CVE/product/build/config/mode/attack-origin/time scope')
        return result
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', binding['cve']): raise ValueError('Invalid CVE identifier')
    if packet.get('source_status') == 'Rejected':
        result['missing_evidence'].append('resolve rejected CVE'); return result
    applicability = packet.get('applicability', {})
    if applicability.get('value') not in STATES: raise ValueError('Invalid applicability value')
    applicable = valid_evidence(applicability, binding, at) and applicability['value'] == 'true'
    if not applicable:
        result['missing_evidence'].append('source-backed exact product/build applicability')
        return result
    all_conditions = {}
    for scenario in packet.get('scenarios', []):
        if not isinstance(scenario.get('id'), str) or not scenario['id']: raise ValueError('Scenario ID required')
        ids = [c.get('id') for c in scenario.get('conditions', [])]
        if len(set(ids)) != len(ids): raise ValueError('Duplicate scenario condition IDs')
        if not leaves(scenario['expression']) <= set(ids): raise ValueError('Formula references missing conditions')
        facts = {}
        for condition in scenario['conditions']:
            key = condition['id']; values = set()
            if key in all_conditions and all_conditions[key] != condition:
                raise ValueError('Condition ID reused with different meaning')
            all_conditions[key] = condition
            if condition.get('operator_observable') is True:
                for observation in packet.get('observations', []):
                    if observation.get('condition_id') != key: continue
                    value = observation.get('value')
                    if value not in STATES: raise ValueError('Invalid observation value')
                    if valid_evidence(observation, binding, at) and value != 'unknown': values.add(value)
            facts[key] = next(iter(values)) if len(values) == 1 else 'unknown'
        reviewed = (scenario.get('semantic_reviewed') is True and scenario.get('sufficiency_reviewed') is True
            and valid_evidence(scenario.get('source_evidence'), binding, at)
            and scenario.get('product') == binding['product'])
        value = logic(scenario['expression'], facts) if reviewed else 'unknown'
        result['condition_values'].update(facts)
        result['scenario_results'].append(dict(id=scenario['id'], value=value, reviewed=bool(reviewed)))
    values = [s['value'] for s in result['scenario_results']]
    fixed = packet.get('fix_evidence')
    nonimpact = packet.get('nonimpact_evidence')
    fixed_ok = valid_evidence(fixed, binding, at) and fixed.get('running_fixed_build_verified') is True
    # A blocked observed network path is deliberately insufficient for clearance.
    nonimpact_ok = (valid_evidence(nonimpact, binding, at)
        and nonimpact.get('all_alternative_paths_reviewed') is True
        and nonimpact.get('structural_nonexecution_verified') is True
        and values and all(v == 'false' for v in values))
    affected = 'true' in values
    if sum(map(bool, (affected, fixed_ok, nonimpact_ok))) > 1:
        result['missing_evidence'].append('conflicting impact/fix/nonimpact evidence')
    elif fixed_ok: result['status'] = 'fixed'
    elif nonimpact_ok: result['status'] = 'not_affected'
    elif affected:
        if str(packet.get('action_statement', '')).strip(): result['status'] = 'affected'
        else: result['missing_evidence'].append('response action statement')
    else: result['missing_evidence'].append('reviewed sufficient scenario and complete supporting observations')
    return result


def import_oval_results(xml_text, mappings, binding, evidence):
    """Map explicit OVAL definition results, never unsupported/error to false.

    The caller must bind a reviewed definition to a CVE condition and separately
    verify the scanner host/report digest. No DTD or external entity is accepted.
    """
    if len(xml_text) > 20_000_000 or '<!DOCTYPE' in xml_text.upper() or '<!ENTITY' in xml_text.upper():
        raise ValueError('Unsafe or oversized OVAL document')
    root = ET.fromstring(xml_text)
    if root.tag != '{'+OVAL_NS+'}oval_results': raise ValueError('Expected OVAL results namespace')
    entries = {}
    for definition in root.findall('.//{'+OVAL_NS+'}definition'):
        if definition.get('definition_id'):
            entries.setdefault(definition.get('definition_id'), []).append(definition.get('result'))
    output = []
    for definition, condition in mappings.items():
        raw = entries.get(definition, [])
        value = raw[0] if len(raw) == 1 and raw[0] in ('true', 'false') else 'unknown'
        if evidence.get('report_asset_ref') != binding.get('asset_ref'): value = 'unknown'
        output.append(dict(evidence, binding=deepcopy(binding), condition_id=condition, value=value,
            source=evidence.get('source', 'OVAL result'), tool='OVAL', definition_id=definition,
            report_sha256=hashlib.sha256(xml_text.encode()).hexdigest()))
    return output


def mulval_input(binding, network, services, vulnerabilities, attacker_host):
    """Generate validated standard MulVAL facts. Unknown facts are omitted."""
    def atom(value):
        if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_.:/-]+', value):
            raise ValueError('Unsupported MulVAL atom')
        return "'"+value+"'"
    lines = [f'attackerLocated({atom(attacker_host)}).',f"attackGoal(execCode({atom(binding['asset_ref'])},_))."]
    for edge in network:
        if edge.get('state') == 'true':
            port = edge.get('port')
            if type(port) is not int or not 0 <= port <= 65535: raise ValueError('Invalid network port')
            lines.append(f"hacl({atom(edge['src'])},{atom(edge['dst'])},{atom(edge['protocol'])},{port}).")
    for service in services:
        port = service.get('port')
        if type(port) is not int or not 0 <= port <= 65535: raise ValueError('Invalid service port')
        if service.get('state') == 'true':
            lines.append(f"networkServiceInfo({atom(binding['asset_ref'])},{atom(service['program'])},{atom(service['protocol'])},{port},{atom(service['user'])}).")
    for vuln in vulnerabilities:
        if vuln.get('reviewed') is True and vuln.get('applicable') == 'true':
            lines.append(f"vulExists({atom(binding['asset_ref'])},{atom(vuln['cve'])},{atom(vuln['program'])}).")
            if (vuln.get('exploit_semantics_reviewed') is True
                and vuln.get('exploit_range') in {'remoteExploit','localExploit'}
                and vuln.get('effect') in {'privEscalation','dos','informationLeak'}):
                lines.append(f"vulProperty({atom(vuln['cve'])},{vuln['exploit_range']},{vuln['effect']}).")
    return '\n'.join(sorted(set(lines)))+'\n'


def affected_precision(predictions, gold, threshold=.85):
    """One exact frozen population; unknown positives cannot disappear."""
    if not all(r.get('synthetic') is True for r in gold):
        raise ValueError('Use item4_scoring.score with independently annotated real-asset gold; do not mix provenance')
    p = {r['id']:r for r in predictions}; g = {r['id']:r for r in gold}
    if len(p)!=len(predictions) or len(g)!=len(gold) or not p or p.keys()!=g.keys():
        raise ValueError('Unique identical nonempty prediction/Gold populations required')
    tp=fp=fn=unjudged=abstentions=false_clearances=0
    for key, row in p.items():
        status=row['status']; actual=g[key]['actual_affected']
        if status not in {'affected','fixed','not_affected','under_investigation'}: raise ValueError('Invalid VEX status')
        if actual is not None and type(actual) is not bool: raise ValueError('Invalid Gold label')
        if row.get('binding') != g[key].get('binding'): raise ValueError('Asset scope mismatch')
        tp += status=='affected' and actual is True
        fp += status=='affected' and actual is False
        unjudged += status=='affected' and actual is None
        fn += status!='affected' and actual is True
        abstentions += status=='under_investigation'
        false_clearances += status in {'not_affected','fixed'} and actual is True
    precision=tp/(tp+fp) if tp+fp and not unjudged else None
    lower=tp/(tp+fp+unjudged) if tp+fp+unjudged else None
    synthetic=all(r.get('synthetic') is True for r in gold)
    return dict(cases=len(p), TP=tp, FP=fp, FN_including_abstentions=fn,
        unjudged_predicted_affected=unjudged, false_clearances=false_clearances,
        precision=precision, precision_lower_bound=lower, recall=tp/(tp+fn) if tp+fn else None,
        abstention_fraction=abstentions/len(p), threshold=threshold, threshold_strict=True,
        target_met=precision>threshold if precision is not None else False,
        synthetic=synthetic, real_asset_precision=None if synthetic else precision,
        independent_real_asset_validation=False if synthetic else 'requires provenance audit')
