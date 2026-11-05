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
from src.vex_routing import classify, workflow, policy
from src import vex_roles as VR
from src.cve_source_evidence import catalog
from src.cwe_evidence_policy import metadata as cwe_metadata

TTL = 86400
_lock = threading.RLock()


def get(review_id):
    master = STORE.get('item4_review', review_id)
    if not master:
        raise KeyError('CWE-first review expired or not found. Start the review again.')
    if any(c.get('analysis_route',{}).get('workflow_policy_version') == 'five-branch-v1' for c in master['cases']):
        raise KeyError('This review uses the retired five-path policy. Start a new four-path review; the historical evidence is retained.')
    if any(c.get('analysis_route',{}).get('policy_version')!=policy()['version'] or
           c.get('analysis_route',{}).get('policy_sha256')!=policy()['sha256'] or
           c.get('analysis_route',{}).get('official_metadata_sha256')!=cwe_metadata()['sha256'] for c in master['cases']):
        raise KeyError('CWE evidence policy changed. Start a new review; historical evidence is retained without silently relabeling it.')
    return master


def result(master):
    statements = [deepcopy(master['statements'][c['cve']]) for c in master['cases']]
    n = len(statements)
    counts = dict(Counter(s['status'] for s in statements))
    eligible = [s for s in statements if s['analysis_route']['requirement'] == 'operational_review'
                or s['analysis_route']['route'] == 'source_analysis']
    out = {'schema': 'ics-vex-item4-review/4', 'review_id': master['id'],
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
    out['evidence_history'] = deepcopy(master.get('history', []))
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
              'simulation': simulation, 'sbom': deepcopy(sbom), 'cases': [], 'statements': {},
              'evidence': {}, 'history': []}
    for original in cases:
        c = deepcopy(original)
        c['routing_sources'] = catalog(c['cve'], c.get('description', ''))
        c['analysis_route'] = classify(c)
        c['case_id'] = master['id'] + ':' + c['cve']
        master['cases'].append(c)
        master['evidence'][c['cve']] = {}
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
            'evidence_progress':{'source':False, 'operational':False, 'ready_for_authoring':False,
                'pending':(['Required source analysis is missing.'] if route['source_required'] else []) +
                          (['Required operational review is missing.'] if route['operational_required'] else [])},
            'missing': [{'requirement': reason}]}
    STORE.put('item4_review', master['id'], master, TTL)
    return result(master)


def questions(review_id):
    with _lock:
        master = get(review_id)
        cases = [c for c in master['cases'] if c['analysis_route'].get('operational_required') and
                 (not c['analysis_route'].get('source_required') or
                  master.get('evidence', {}).get(c['cve'], {}).get('source'))]
        if not cases:
            raise ValueError('No CVEs are eligible for operational questions. Supply required source or resolve routing evidence.')
        # Reopening the form must retain question IDs and entered answers.
        if master.get('operational_plan_id') and master.get('operational_plan_cves') == [c['cve'] for c in cases]:
            plan = STORE.get('plan', master['operational_plan_id'])
            if plan:
                return {**OQ.public(plan), 'review_id': review_id, 'routes': {c['cve']: c['analysis_route'] for c in master['cases']}}
        plan = OQ.create(cases, master['product'], review_id, master['simulation'],
                         sbom=master.get('sbom'), question_role='item4-questions')
        master['operational_plan_id'] = plan['id']
        master['operational_plan_cves'] = [c['cve'] for c in cases]
        STORE.put('item4_review', review_id, master, TTL)
        return {**plan, 'review_id': review_id, 'routes': {c['cve']: c['analysis_route'] for c in master['cases']}}


def _combine(master, c):
    """Single deterministic decision from the accumulated, CVE-scoped evidence."""
    evidence = master['evidence'][c['cve']]
    source, operating = evidence.get('source'), evidence.get('operational')
    route = c['analysis_route']
    missing = []
    if route['source_required'] and not source:missing.append('Required source analysis is missing.')
    if route['operational_required'] and not operating:missing.append('Required operational review is missing.')
    base = deepcopy(source or operating or master['statements'][c['cve']])
    if source and operating:
        for key in ('operational_review', 'operational_assessment'):
            if key in operating:base[key] = deepcopy(operating[key])
        decisions = {s['status'] for s in (source, operating)} - {'under_investigation'}
        if len(decisions) > 1:
            missing.append('Source and operational decisions conflict; reconcile scope and build identity.')
        elif decisions:
            selected = source if source['status'] in decisions else operating
            base.update({k:deepcopy(selected.get(k)) for k in ('status','justification','reason','scope')})
        base['missing'] = deepcopy(source.get('missing', [])) + deepcopy(operating.get('missing', []))
    base['arm'] = 'combined-evidence' if source and operating else base.get('arm', 'routing-deferred')
    base['analysis_route'] = deepcopy(route)
    base['case_id'] = c['case_id']
    base['evidence_progress'] = {'source':bool(source), 'operational':bool(operating),
                               'pending':missing, 'ready_for_authoring':not missing}
    base['branch_evidence'] = deepcopy(evidence)
    if missing:
        base.update(status='under_investigation', justification=None, reason=' '.join(missing),
                    document_draft=None, pipeline_complete=False,
                    authoring={'status':'waiting_for_evidence', 'prediction':None, 'reason':' '.join(missing)})
        base['missing'] = base.get('missing', []) + [{'requirement':m} for m in missing]
        base.setdefault('extraction', {'status':'not_run', 'usable':False})
    else:
        prepared = VR.prepare([c], product=master['product'], run_id=master['id'], simulation=master['simulation'])
        signature = VR.fingerprint([evidence, route])
        previous = master['statements'][c['cve']]
        if previous.get('authoring_evidence_sha256') == signature:
            return previous
        base = VR.finish({'statements':[base]}, prepared)['statements'][0]
        base['authoring_evidence_sha256'] = signature
    return base


def _update(master, statements, requirement):
    known = {c['cve']: c for c in master['cases']}
    key = 'source' if requirement == 'source_required' else 'operational'
    flag = 'source_required' if key == 'source' else 'operational_required'
    if len({s['cve'] for s in statements}) != len(statements) or any(s['cve'] not in known or not known[s['cve']]['analysis_route'].get(flag) for s in statements):
        raise ValueError('Result contains a CVE outside the authorized evidence branch.')
    for s in statements:
        c = known[s['cve']]
        bucket = master.setdefault('evidence', {}).setdefault(s['cve'], {})
        bucket[key] = deepcopy(s)
        c['analysis_route'] = workflow(c['analysis_route'], source_available=bool(bucket.get('source')))
        master.setdefault('history', []).append({'cve':s['cve'], 'case_id':c['case_id'], 'evidence_kind':key,
            'sha256':VR.fingerprint(s), 'recorded_at':time.time(), 'workflow_branch':c['analysis_route']['workflow_branch']})
        master['statements'][s['cve']] = _combine(master, c)
    STORE.put('item4_review', master['id'], master, TTL)
    return result(master)


def answers(review_id, values, component_facts=None, *, plan_id=None):
    with _lock:
        master = get(review_id)
        if not master.get('operational_plan_id'):
            raise ValueError('Generate operational questions for this review first.')
        if plan_id is not None and plan_id != master['operational_plan_id']:
            raise ValueError('Questionnaire does not belong to the current review plan. Reopen the form.')
        assessed = OQ.assess(master['operational_plan_id'], values, component_facts, author=False)
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
