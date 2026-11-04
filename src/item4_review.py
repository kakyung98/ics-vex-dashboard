"""Persist the CWE-first #4 review, including mixed evidence branches.

Routing is a versioned project policy prediction, not expert ground truth.
Blocked cases never enter the operational LLM pipeline.
"""
from copy import deepcopy
from collections import Counter
import time
import uuid
import threading
from src import review_store as STORE
from src import operational_questions as OQ
from src.vex_routing import classify
from src.cve_source_evidence import catalog

TTL = 86400
_lock = threading.RLock()


def get(review_id):
    master = STORE.get('item4_review', review_id)
    if not master:
        raise KeyError('CWE-first review expired or not found. Start the review again.')
    return master


def result(master):
    statements = [deepcopy(master['statements'][c['cve']]) for c in master['cases']]
    n = len(statements)
    counts = dict(Counter(s['status'] for s in statements))
    eligible = [s for s in statements if s['analysis_route']['requirement'] == 'operational_review'
                or s['analysis_route']['route'] == 'source_analysis']
    out = {'schema': 'ics-vex-item4-review/3', 'review_id': master['id'],
           'arm': 'cwe-first', 'statements': statements, 'total': n, 'by_status': counts,
           'deferred': counts.get('under_investigation', 0),
           'deferral_rate': counts.get('under_investigation', 0) / n,
           'decision_rate': 1 - counts.get('under_investigation', 0) / n,
           'routes': {c['cve']: c['analysis_route'] for c in master['cases']},
           'pipeline': {'name': 'CWE-first evidence review', 'case_count': n,
                        'model_eligible_cases': len(eligible),
                        'complete_cases': sum(bool(s.get('pipeline_complete')) for s in statements),
                        'extraction_status': dict(Counter(s['extraction']['status'] for s in statements)),
                        'authoring_status': dict(Counter(s['authoring']['status'] for s in statements)),
                        'stages': ['cwe_pillar_routing', 'required_evidence_branch', 'locked_vex_decision', 'validated_export'],
                        'answer_key_used': False, 'review_required': True},
           'vex_drafts': [s['document_draft'] for s in statements if s.get('document_draft')],
           'routing_is_independently_validated': False,
           'component_facts': deepcopy(master.get('component_facts', {}))}
    sbom = master.get('sbom')
    if sbom and sbom.get('bomFormat') == 'CycloneDX':
        from src.sbom_vex import merge
        from src.sbom_schema import validate
        out['sbom_vex'] = merge(sbom, out, master['cases'])
        out['sbom_vex_validation'] = validate(out['sbom_vex'])
    elif sbom:
        out['sbom_vex_validation'] = {'status': 'unavailable', 'reason': 'Use standalone VEX for SPDX input.'}
    return out


def start(cases, product='unspecified-product', simulation=False, sbom=None):
    if not 1 <= len(cases) <= 100 or len({c['cve'] for c in cases}) != len(cases):
        raise ValueError('Provide 1 to 100 distinct CVEs.')
    master = {'id': uuid.uuid4().hex, 'created_at': time.time(), 'product': product,
              'simulation': simulation, 'sbom': deepcopy(sbom), 'cases': [], 'statements': {}}
    for original in cases:
        c = deepcopy(original)
        c['routing_sources'] = catalog(c['cve'], c.get('description', ''))
        c['analysis_route'] = classify(c)
        c['case_id'] = master['id'] + ':' + c['cve']
        master['cases'].append(c)
        route = c['analysis_route']
        reason = route['reason']
        if route['requirement'] == 'operational_review':
            reason = 'Operator answers and source-linked common / CVE-specific questions are pending.'
        master['statements'][c['cve']] = {
            'cve': c['cve'], 'case_id': c['case_id'], 'status': 'under_investigation',
            'justification': None, 'reason': reason, 'arm': 'routing-deferred',
            'scope': 'CWE-first evidence routing; no completed exploitability analysis',
            'analysis_route': route, 'extraction': {'status': 'not_run', 'usable': False},
            'authoring': {'status': 'not_run', 'prediction': None, 'reason': reason},
            'document_draft': None, 'pipeline_complete': False, 'review_required': True,
            'missing': [{'requirement': reason}]}
    STORE.put('item4_review', master['id'], master, TTL)
    return result(master)


def questions(review_id):
    with _lock:
        master = get(review_id)
        cases = [c for c in master['cases'] if c['analysis_route']['requirement'] == 'operational_review']
        if not cases:
            raise ValueError('No CVEs are eligible for operational questions. Supply required source or resolve routing evidence.')
        plan = OQ.create(cases, master['product'], review_id, master['simulation'],
                         sbom=master.get('sbom'), question_role='item4-questions')
        master['operational_plan_id'] = plan['id']
        STORE.put('item4_review', review_id, master, TTL)
        return {**plan, 'review_id': review_id, 'routes': {c['cve']: c['analysis_route'] for c in master['cases']}}


def _update(master, statements, requirement):
    known = {c['cve']: c for c in master['cases']}
    if any(s['cve'] not in known or known[s['cve']]['analysis_route']['requirement'] != requirement for s in statements):
        raise ValueError('Result contains a CVE outside the authorized evidence branch.')
    for s in statements:
        c = known[s['cve']]
        if requirement == 'source_required':
            c['analysis_route'] = classify(c, source_available=True)
        master['statements'][s['cve']] = {**deepcopy(s), 'analysis_route': deepcopy(c['analysis_route'])}
    STORE.put('item4_review', master['id'], master, TTL)
    return result(master)


def answers(review_id, values, component_facts=None):
    with _lock:
        master = get(review_id)
        if not master.get('operational_plan_id'):
            raise ValueError('Generate operational questions for this review first.')
        assessed = OQ.assess(master['operational_plan_id'], values, component_facts)
        master['component_facts'] = assessed.get('component_facts', {})
        out = _update(master, assessed['statements'], 'operational_review')
        return out


def record_source(review_id, source_result):
    with _lock:
        out = _update(get(review_id), source_result['statements'], 'source_required')
        for k in ('cfg', 'tree_completeness_declaration', 'indirect_call_sites'):
            if k in source_result:
                out[k] = source_result[k]
        return out
