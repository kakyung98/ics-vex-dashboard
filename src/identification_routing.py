"""Conditional item-3 agent execution, with independently checked decisions."""
from copy import deepcopy
from functools import lru_cache
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

POLICY = 'item3-conditional-routing-v1'
TASKS = ('L2', 'L3', 'L4')  # Persisted model role IDs; public names are P2/P3/P4.


class IdentificationState(TypedDict):
    component: dict
    versions: dict
    prepared: dict
    validation: dict
    index: Any
    infer: Any
    synthetic: bool
    allow_declared_cpe_version: bool
    notify: Any
    decisions: dict
    completed: list
    trace: list


def conditions(component, versions, prepared, index):
    from src.identity_evidence import validate_identity
    from ics_agent_matcher_full.ics_agent_matcher.matcher import norm

    baseline = validate_identity(component, prepared['candidates'])
    missing_name = norm(component.get('name') or '') in ('', 'unknown', 'unspecified', 'noassertion')
    p2 = []
    if missing_name:
        p2.append('product_name_missing')
    if baseline['status'] != 'validated':
        p2.append('product_name_ambiguous_or_unsupported')
    p3 = []
    if versions.get('normalized') is None and not versions.get('declared_range'):
        p3.append('version_missing_or_unresolved')
    if versions.get('conflicts'):
        p3.append('version_sources_conflict')
    if any(o['source'] == 'name' or o['kind'] != 'exact' for o in versions.get('observations', [])):
        p3.append('version_notation_or_model_requires_review')
    raw_version = str(versions.get('raw') or '')
    if versions.get('normalized') is not None and raw_version and raw_version != versions['normalized']:
        p3.append('version_notation_requires_normalization')
    checks = index.check_cpes(component)
    # Either a usable CPE or a parsed, matching PURL can supply an identifier.
    selected = baseline.get('selected_candidate_id')
    cpe_ok = bool(checks) and all(c['usable_identity'] and c['candidate_id'] == selected for c in checks)
    purl = versions.get('purl')
    purl_ok = bool(purl and baseline['status'] == 'validated'
                   and norm(purl['name']) == norm(baseline['product']))
    p4 = []
    if not component.get('cpes') and not component.get('purl'):
        p4.append('identifier_missing')
    elif not (cpe_ok or purl_ok):
        p4.append('identifier_unverified_or_mismatched')
    if checks and not cpe_ok:
        p4.append('reported_cpe_conflict_or_unverified')
    if component.get('purl') and not purl_ok:
        p4.append('reported_purl_conflict_or_unverified')
    if baseline['status'] != 'validated':
        p4.append('identity_requires_review')
    return {task: {'label': 'P' + task[1], 'required': bool(reasons),
                   'reasons': reasons or ['sufficient_structured_evidence']}
            for task, reasons in zip(TASKS, (p2, p3, p4))}


def _orchestrator(state):
    decisions = deepcopy(state['decisions'])
    fresh = conditions(state['component'], state['versions'], state['prepared'], state['index'])
    for task in TASKS:
        if task not in state['completed']:
            decisions[task] = fresh[task]
    return {'decisions': decisions, 'trace': [*state['trace'], 'orchestrator']}


def _next(state):
    return next((task for task in TASKS if task not in state['completed']
                 and state['decisions'][task]['required']), 'decision_validator')


def _agent(state, task):
    from src.identification_agent_flow import review_rank, review_versions, revalidate_rank, review_identity
    from src.identity_evidence import validate_identity
    from src.l2_candidates import rank

    if state['notify']:
        state['notify'](task.lower() + '_agent')
    c, versions, prepared = state['component'], state['versions'], state['prepared']
    if task == 'L2':
        prepared = review_rank(c, prepared, state['infer'])
    elif task == 'L3':
        versions = review_versions(c, versions, state['index'], state['infer'], state['synthetic'],
                                   allow_declared_cpe_version=state['allow_declared_cpe_version'])
        retrieval = state['index'].search(c, versions)
        if 'L2' in state['completed']:
            prepared = revalidate_rank(c, versions, prepared, retrieval)
        else:
            prepared = rank(c, versions, retrieval, None)
    else:
        baseline = validate_identity(c, prepared['candidates'])
        validation = review_identity(c, prepared, baseline, state['infer'],
                                     require_rank_review='L2' in state['completed'])
        return {'validation': validation, 'completed': [*state['completed'], task],
                'trace': [*state['trace'], 'P4']}
    return {'versions': versions, 'prepared': prepared, 'completed': [*state['completed'], task],
            'trace': [*state['trace'], 'P' + task[1]]}


def _validate(state):
    from src.identity_evidence import validate_identity
    baseline = validate_identity(state['component'], state['prepared']['candidates'])
    validation = deepcopy(state['validation'] if 'L4' in state['completed'] else baseline)
    reasons = list(validation.get('reasons', []))
    if 'L2' in state['completed']:
        agent = state['prepared']['agent']
        prediction = agent.get('prediction') or {}
        if not (agent.get('guard_accepted') and prediction.get('status') == 'ranked'
                and baseline.get('selected_candidate_id') in prediction.get('ranked_candidate_ids', [])):
            reasons.append('L2_agent_not_confirmed')
    if baseline['status'] != 'validated' or (validation.get('selected_candidate_id') != baseline.get('selected_candidate_id')):
        reasons.extend(baseline.get('reasons', []))
        reasons.append('final_dictionary_evidence_not_confirmed')
    if '\\' in state['component'].get('name', ''):
        reasons.append('escaped_identifier_requires_review')
    if reasons:
        validation.update(status='unresolved', identity_status=baseline['identity_status'] if baseline['status'] != 'validated' else 'insufficient_evidence',
                          vendor=None, product=None, part=None, selected_candidate_id=None,
                          evidence_refs=[], reasons=list(dict.fromkeys(reasons)),
                          acceptance_rule='defer_unaccepted_agent_or_unsupported_identity_evidence')
    # No model record is invented for a skipped stage.
    if 'L4' not in state['completed']:
        validation['agent'] = skipped('L4', state['decisions']['L4'])
    if state['notify']:
        state['notify']('decision_validator')
    return {'validation': validation, 'trace': [*state['trace'], 'decision_validator']}


def skipped(task, decision):
    return {'task': task, 'label': 'P' + task[1], 'executed': False, 'llm_used': False,
            'status': 'skipped', 'guard_accepted': False, 'fine_tuned_for_role': False,
            'reason': 'conditional_routing_not_required', 'routing_reasons': decision['reasons']}


@lru_cache(maxsize=1)
def graph():
    builder = StateGraph(IdentificationState)
    builder.add_node('orchestrator', _orchestrator)
    for task in TASKS:
        builder.add_node(task, lambda state, task=task: _agent(state, task))
        builder.add_edge(task, 'orchestrator')
    builder.add_node('decision_validator', _validate)
    builder.add_edge(START, 'orchestrator')
    builder.add_conditional_edges('orchestrator', _next, {t: t for t in (*TASKS, 'decision_validator')})
    builder.add_edge('decision_validator', END)
    return builder.compile()


def route_component(component, versions, prepared, index, infer, *, synthetic=False,
                    allow_declared_cpe_version=False, notify=None):
    decisions = conditions(component, versions, prepared, index)
    state = graph().invoke({'component': component, 'versions': versions, 'prepared': prepared,
                            'validation': {}, 'index': index, 'infer': infer, 'synthetic': synthetic,
                            'allow_declared_cpe_version': allow_declared_cpe_version,
                            'notify': notify, 'decisions': decisions, 'completed': [], 'trace': []})
    for task, target in (('L2', state['prepared']), ('L3', state['versions'])):
        if task not in state['completed']:
            target['agent'] = skipped(task, state['decisions'][task])
    records = {'L2': state['prepared']['agent'], 'L3': state['versions']['agent'],
               'L4': state['validation']['agent']}
    state['routing'] = {'policy': POLICY, 'engine': 'langgraph.StateGraph',
                        'initial_decisions': decisions, 'decisions': state['decisions'],
                        'selected_agents': ['P' + t[1] for t in state['completed']],
                        'executed_agents': ['P' + t[1] for t in state['completed'] if records[t].get('executed')],
                        'blocked_agents': ['P' + t[1] for t in state['completed'] if not records[t].get('executed')],
                        'skipped_agents': ['P' + t[1] for t in TASKS if t not in state['completed']],
                        'trace': state['trace']}
    return state
