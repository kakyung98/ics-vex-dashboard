"""Conditional item-3 agent execution, with independently checked decisions."""
from copy import deepcopy
from functools import lru_cache
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

POLICY = 'item3-conditional-routing-v3'
TASKS = ('I1', 'I2', 'I3')


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


def conditions(component, versions, prepared, index, *, model_review=False):
    from src.item3.evidence.product_identity_evidence import validate_identity,eligible_identities
    from src.item3.matching.sbom_matching_engine import norm

    baseline = validate_identity(component, prepared['candidates'])
    supported=eligible_identities(component,prepared['candidates'])
    missing_name = norm(component.get('name') or '') in ('', 'unknown', 'unspecified', 'noassertion')
    i1 = []
    if missing_name and baseline['status'] != 'validated':
        i1.append('product_name_missing')
    # The final evidence gate requires a unique independent identity. A model
    # ranking cannot make multiple independently supported identities unique;
    # retain the ranked candidates and defer that ambiguity directly.
    if baseline['status'] != 'validated':i1=[]
    # Ranking cannot manufacture the independent evidence required by the final
    # gate. Retain the candidates and deterministic unresolved result instead of
    # paying for a model choice that is unable to confirm any supplied identity.
    if not supported:i1=[]
    # Model review includes product ranking even when structured evidence is
    # already exact. Previously the branches above cleared every I1 request.
    # Ranking still cannot override the independent identity evidence gate.
    if model_review and any(not c['conflicts'] for c in prepared['candidates']):
        i1 = ['require_model_product_ranking']
    i2 = []
    if versions.get('normalized') is None and not versions.get('declared_range'):
        i2.append('version_missing_or_unresolved')
    if versions.get('conflicts'):
        i2.append('version_sources_conflict')
    if any(o['source'] == 'name' or o['kind'] != 'exact' for o in versions.get('observations', [])):
        i2.append('version_notation_or_model_requires_review')
    raw_version = str(versions.get('raw') or '')
    if versions.get('normalized') is not None and raw_version and raw_version != versions['normalized']:
        i2.append('version_notation_requires_normalization')
    checks = index.check_cpes(component)
    # Either a usable CPE or a parsed, matching PURL can supply an identifier.
    selected = baseline.get('selected_candidate_id')
    # Declared releases and editions are checked against CVE conditions later.
    # A model cannot turn an unregistered release into a registry entry; the
    # product identity can already be independently known from the dictionary.
    cpe_ok = bool(checks) and all(c['usable_product_identity'] and c['candidate_id'] == selected for c in checks)
    purl = versions.get('purl')
    purl_ok = bool(purl and baseline['status'] == 'validated'
                   and norm(purl['name']) == norm(baseline['product']))
    i3 = []
    if not component.get('cpes') and not component.get('purl') and baseline['status'] != 'validated':
        i3.append('identifier_missing')
    elif (component.get('cpes') or component.get('purl')) and not (cpe_ok or purl_ok):
        i3.append('identifier_unverified_or_mismatched')
    if checks and not cpe_ok:
        i3.append('reported_cpe_conflict_or_unverified')
    if component.get('purl') and not purl_ok:
        i3.append('reported_purl_conflict_or_unverified')
    if baseline['status'] != 'validated':i3=[]
    if baseline['status']=='validated':i3=[]
    if not supported:i3=[]
    if model_review and baseline['status'] == 'validated':
        i3 = ['require_model_identity_decision']
    return {task: {'label': task, 'required': bool(reasons),
                   'reasons': reasons or (['no_unique_independently_supported_identity'] if supported and baseline['status']!='validated' and task in ('I1','I3') else ['no_independently_supported_identity'] if not supported and task in ('I1','I3') else ['sufficient_structured_evidence'])}
            for task, reasons in zip(TASKS, (i1, i2, i3))}


def _orchestrator(state):
    decisions = deepcopy(state['decisions'])
    fresh = conditions(state['component'], state['versions'], state['prepared'], state['index'], model_review=getattr(state['infer'], 'require_identity_review', False))
    for task in TASKS:
        if task not in state['completed']:
            decisions[task] = fresh[task]
    return {'decisions': decisions, 'trace': [*state['trace'], 'orchestrator']}


def _next(state):
    return next((task for task in TASKS if task not in state['completed']
                 and state['decisions'][task]['required']), 'decision_validator')


def _agent(state, task):
    from src.item3.agents.evidence_review_agents import review_rank; from src.item3.agents.evidence_review_agents import review_versions; from src.item3.agents.evidence_review_agents import revalidate_rank; from src.item3.agents.evidence_review_agents import review_identity
    from src.item3.evidence.product_identity_evidence import validate_identity
    from src.item3.matching.product_candidate_ranking import rank

    if state['notify']:
        state['notify'](task.lower() + '_agent')
    c, versions, prepared = state['component'], state['versions'], state['prepared']
    if task == 'I1':
        prepared = review_rank(c, prepared, state['infer'])
    elif task == 'I2':
        versions = review_versions(c, versions, state['index'], state['infer'], state['synthetic'],
                                   allow_declared_cpe_version=state['allow_declared_cpe_version'])
        from src.item3.evidence.product_identity_evidence import prepare_candidates
        retrieval,fresh_prepared = prepare_candidates(c,versions,state['index'])
        if 'I1' in state['completed']:
            prepared = revalidate_rank(c, versions, prepared, retrieval)
        else:
            prepared = fresh_prepared
    else:
        baseline = validate_identity(c, prepared['candidates'])
        validation = review_identity(c, prepared, baseline, state['infer'],
                                     require_rank_review='I1' in state['completed'])
        return {'validation': validation, 'completed': [*state['completed'], task],
                'trace': [*state['trace'], 'I3']}
    return {'versions': versions, 'prepared': prepared, 'completed': [*state['completed'], task],
            'trace': [*state['trace'], task]}


def _validate(state):
    from src.item3.evidence.product_identity_evidence import validate_identity
    baseline = validate_identity(state['component'], state['prepared']['candidates'])
    validation = deepcopy(state['validation'] if 'I3' in state['completed'] else baseline)
    reasons = list(validation.get('reasons', []))
    if 'I1' in state['completed']:
        agent = state['prepared']['agent']
        prediction = agent.get('prediction') or {}
        if not (agent.get('guard_accepted') and prediction.get('status') == 'ranked'
                and (not getattr(state['infer'], 'require_identity_review', False) or agent.get('llm_used'))
                and baseline.get('selected_candidate_id') in prediction.get('ranked_candidate_ids', [])):
            reasons.append('I1_agent_not_confirmed')
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
    if 'I3' not in state['completed']:
        validation['agent'] = skipped('I3', state['decisions']['I3'])
    if state['notify']:
        state['notify']('decision_validator')
    return {'validation': validation, 'trace': [*state['trace'], 'decision_validator']}


def skipped(task, decision):
    return {'task': task, 'label': task, 'executed': False, 'llm_used': False,
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
    decisions = conditions(component, versions, prepared, index, model_review=getattr(infer, 'require_identity_review', False))
    initial={'component': component, 'versions': versions, 'prepared': prepared,
                            'validation': {}, 'index': index, 'infer': infer, 'synthetic': synthetic,
                            'allow_declared_cpe_version': allow_declared_cpe_version,
                            'notify': notify, 'decisions': decisions, 'completed': [], 'trace': []}
    if any(decision['required'] for decision in decisions.values()):
        state=graph().invoke(initial)
    else:
        initial['trace']=['orchestrator']
        state={**initial,**_validate(initial)}
    for task, target in (('I1', state['prepared']), ('I2', state['versions'])):
        if task not in state['completed']:
            target['agent'] = skipped(task, state['decisions'][task])
    records = {'I1': state['prepared']['agent'], 'I2': state['versions']['agent'],
               'I3': state['validation']['agent']}
    state['routing'] = {'policy': POLICY, 'engine': 'langgraph.StateGraph',
                        'initial_decisions': decisions, 'decisions': state['decisions'],
                        'selected_agents': [t for t in state['completed']],
                        'executed_agents': [t for t in state['completed'] if records[t].get('executed')],
                        'blocked_agents': [t for t in state['completed'] if not records[t].get('executed')],
                        'skipped_agents': [t for t in TASKS if t not in state['completed']],
                        'trace': state['trace']}
    return state
