"""LLM evidence review with independent dictionary/version gates and explicit deferral."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from src.identification_agent_contracts import VERSION, validate

ROOT = Path(__file__).resolve().parents[1]


def configured_mode():
    mode = os.environ.get('ICSVEX_IDENTIFICATION_MODE')
    if mode is None:
        path = ROOT / 'data/identification_runtime.json'
        mode = json.loads(path.read_text(encoding='utf-8')).get('mode', 'agents') if path.is_file() else 'agents'
    if mode not in {'agents', 'rules'}:
        raise ValueError('Identification mode must be agents or rules.')
    return mode


def call(task, packet, infer):
    record = {'task': task, 'executed': True, 'contract': VERSION,
              'input_sha256': hashlib.sha256(json.dumps(packet, sort_keys=True).encode()).hexdigest(),
              'fine_tuned_for_role': False, 'legacy_identification_adapters_used': False}
    try:
        result = infer(task, packet)
        if not isinstance(result, dict):
            raise ValueError('Invalid inference response')
        record.update({k: result[k] for k in ['raw', 'error', 'model', 'model_mode', 'adapter', 'generation','wire_prediction','identifier_aliases','transport'] if k in result})
        pred = result.get('prediction')
        record['fine_tuned_for_role']=result.get('model_mode')=='fine_tuned'
        if task == 'L3' and isinstance(pred, dict) and not validate(task, packet, pred):
            # The observation IDs already reference exact supplied evidence. Repair
            # missing citations only; never repair classifications or unknown IDs.
            repaired = deepcopy(pred)
            selected = set(pred.get('version_observation_ids', []) + pred.get('model_observation_ids', []))
            available = {o['id'] for o in packet['observations']}
            if selected <= available and pred.get('evidence_refs') == []:
                repaired['evidence_refs'] = list(dict.fromkeys([*pred['evidence_refs'], *sorted(selected)]))
                if validate(task, packet, repaired):
                    record['original_prediction'] = deepcopy(pred)
                    record['evidence_repair'] = 'cite_exact_selected_input_observations'
                    pred = repaired
        record.update(prediction=pred, llm_used=result.get('llm_used', pred is not None))
        accepted = validate(task, packet, pred)
        record.update(status=('abstained' if accepted and pred['status'] == 'unresolved' else 'validated' if accepted else 'unavailable' if pred is None else 'rejected'),
                      guard_accepted=accepted, schema_valid=accepted)
        if not accepted:
            record['error'] = record.get('error') or 'ungrounded_agent_output'
    except Exception as exc:
        record.update(status='unavailable', prediction=None, llm_used=False, guard_accepted=False,
                      schema_valid=False, error=type(exc).__name__ + ': ' + str(exc))
    return record


def review_versions(component, baseline, index, infer, synthetic=False,allow_declared_cpe_version=False):
    from src.identity_evidence import grounded_versions
    from src.identity_retrieval import vendor_key
    from ics_agent_matcher_full.ics_agent_matcher.matcher import norm
    exact = index.by_product.get(norm(component.get('name')), set())
    manufacturer = vendor_key(component.get('manufacturer'))
    if manufacturer:
        exact = {rid for rid in exact if vendor_key(index.docs[rid]['vendor']) == manufacturer}
    types = {'application': {'a'}, 'library': {'a'}, 'operating-system': {'o'}, 'device': {'h'}, 'firmware': {'a', 'o'}}
    allowed = types.get(component.get('component_type'))
    if allowed:
        exact = {rid for rid in exact if index.docs[rid]['part'] in allowed}
    known_model_name = len(exact) == 1
    observations = [{**o, 'id': f'observation:{i}',
                     'may_be_model_identifier': o['source'] == 'name' and known_model_name}
                    for i, o in enumerate(baseline.get('observations', []))]
    evidence = deepcopy(component['evidence']) + [{'id': o['id'], 'source': o['source'], 'value': o['raw']} for o in observations]
    packet = {'contract': VERSION, 'component': {k: component.get(k) for k in ['name', 'version', 'manufacturer', 'purl', 'cpes']},
              'observations': observations, 'evidence': evidence}
    agent = call('L3', packet, infer)
    if not agent['guard_accepted'] or agent['prediction']['status'] == 'unresolved':
        out = deepcopy(baseline)
        # Explicit, mutually consistent source fields are independent evidence.
        # Reject a bad agent response without deleting those original facts.
        direct_only = (any(o['source'] != 'name' and o['kind'] == 'exact' for o in observations)
                       and baseline.get('normalized') is not None and not baseline.get('conflicts'))
        if direct_only:
            out['classification_basis'] = 'unambiguous_explicit_input_preserved_after_agent_deferral'
        else:
            out.update(normalized=None, comparison_version=None, declared_range=None, status='agent_unresolved')
            out['missing_evidence'] = [*out.get('missing_evidence', []), 'Accepted P3 agent evidence classification']
    else:
        models = set(agent['prediction']['model_observation_ids'])
        masked = deepcopy(component)
        name = list(component['name'])
        for o in observations:
            if o['id'] in models:
                start, end = o['span']
                name[start:end] = ' ' * (end - start)
        masked['name'] = ''.join(name)
        out = grounded_versions(masked, index, synthetic,allow_declared_cpe_version=allow_declared_cpe_version)
        # Restore original text in retained observation evidence and preserve excluded facts.
        for o in out.get('observations', []):
            if o['source'] == 'name':
                o['evidence'] = component['name'][o['span'][0]:o['span'][1]]
        out['catalog_model_observations'] = [o for o in observations if o['id'] in models]
    out['agent'] = agent
    return out


def review_rank(component, prepared, infer):
    candidates = deepcopy(prepared['candidates'])
    packet = deepcopy(prepared['packet'])
    packet['contract'] = VERSION
    if len(candidates) > 30:
        agent = {'task': 'L2', 'executed': False, 'llm_used': False, 'guard_accepted': False,
                 'status': 'unavailable', 'error': 'too_many_competing_candidates', 'contract': VERSION}
    else:
        agent = call('L2', packet, infer)
    if agent['guard_accepted'] and agent['prediction']['status'] == 'ranked':
        order = {identifier: i for i, identifier in enumerate(agent['prediction']['ranked_candidate_ids'])}
        candidates.sort(key=lambda c: order.get(c['candidate_id'], len(order)))
        state = 'ranked'
    else:
        state = 'unresolved'
    return {**prepared, 'candidates': candidates, 'status': state, 'agent': agent,
            'method': 'grounded P2 agent ranking over dictionary candidates'}


def revalidate_rank(component, versions, prepared, retrieval):
    """Recheck source gates after P3 without inventing a second P2 decision.

    Keep the exact packet and agent record from P2. Re-retrieval may expose new
    competitors or conflicts, which must reach identity validation even if they
    were absent from the original P2 packet. Only IDs actually ranked by the
    accepted P2 response can subsequently be selected by P4.
    """
    from src.l2_candidates import rank
    refreshed = rank(component, versions, retrieval, None)
    before = {c['candidate_id'] for c in prepared['candidates']}
    after = {c['candidate_id'] for c in refreshed['candidates']}
    prediction = prepared['agent'].get('prediction') or {}
    order = {rid: i for i, rid in enumerate(prediction.get('ranked_candidate_ids', []))}
    refreshed['candidates'].sort(key=lambda c: order.get(c['candidate_id'], len(order)))
    return {**prepared, 'candidates': refreshed['candidates'],
            'post_l3_validation': {
                'method': 'fresh_dictionary_retrieval_and_source_model_checks',
                'structured_input': refreshed['structured_input'],
                'retrieval': refreshed['retrieval'],
                'added_candidate_ids': sorted(after - before),
                'removed_candidate_ids': sorted(before - after),
                'l2_prediction_reused_verbatim': True}}


def review_identity(component, prepared, baseline, infer, *, require_rank_review=True):
    candidates = prepared['candidates']
    l2_ready = prepared['agent'].get('guard_accepted') and prepared['agent'].get('prediction', {}).get('status') == 'ranked'
    ranked_ids = set((prepared['agent'].get('prediction') or {}).get('ranked_candidate_ids', []))
    if not require_rank_review:
        # P2 bypass requires independently validated dictionary evidence.
        l2_ready = baseline['status'] == 'validated'
        ranked_ids = {baseline['selected_candidate_id']} if l2_ready else set()
    unsupported_escape = '\\' in component.get('name', '')
    evidence = deepcopy(component['evidence']) + [{'id': 'dictionary:' + c['candidate_id'], 'value': {k: c[k] for k in ['part', 'vendor', 'product', 'cpe']}}
                                               for c in candidates]
    packet = {'contract': VERSION, 'component': {k: component.get(k) for k in ['name', 'manufacturer', 'supplier', 'component_type', 'cpes']},
              'candidates': [{**{k: c[k] for k in ['candidate_id', 'part', 'vendor', 'product', 'conflicts']},
                              'eligible_for_selection': bool(l2_ready and not unsupported_escape and baseline['status'] == 'validated'
                                                             and not c['conflicts'] and c['candidate_id'] in ranked_ids
                                                             and c['candidate_id'] == baseline['selected_candidate_id'])}
                             for c in candidates], 'evidence': evidence}
    agent = call('L4', packet, infer)
    selected = (agent.get('prediction') or {}).get('candidate_id')
    if (agent['guard_accepted'] and agent['prediction']['status'] == 'validated'
            and l2_ready and not unsupported_escape and selected in ranked_ids
            and baseline['status'] == 'validated' and selected == baseline['selected_candidate_id']):
        result = deepcopy(baseline)
        result['acceptance_rule'] = 'L4_agent_selection_and_independent_dictionary_evidence_validation'
    else:
        reasons = list(baseline.get('reasons', []))
        reasons += ['escaped_identifier_requires_review'] if unsupported_escape else ['L4_agent_not_confirmed']
        if not l2_ready:
            reasons.append('L2_agent_not_confirmed')
        elif baseline.get('selected_candidate_id') not in ranked_ids and baseline['status'] == 'validated':
            reasons.append('L2_candidate_not_ranked')
        result = {**baseline, 'status': 'unresolved', 'identity_status': 'insufficient_evidence',
                  'vendor': None, 'product': None, 'part': None, 'selected_candidate_id': None,
                  'reasons': list(dict.fromkeys(reasons)), 'evidence_refs': [],
                  'acceptance_rule': 'defer_unaccepted_agent_or_unsupported_identity_evidence'}
    result['agent'] = agent
    return result
