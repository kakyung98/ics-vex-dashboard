"""Persist operational-context reviews and their CVE-scoped evidence."""
from collections import Counter
from copy import deepcopy
import threading
import time
import uuid
from src import review_store as STORE
from src import operational_questions as OQ
from src import vex_roles as VR
from src.vex_routing import classify, VERSION

TTL = 86400
_lock = threading.RLock()


def get(review_id):
    master = STORE.get('item4_review', review_id)
    if not master:
        raise KeyError('Review expired or not found. Start the review again.')
    if master.get('policy_version') != VERSION:
        raise KeyError('This review predates operational-only review. Start a new review; historical records are retained.')
    return master


def result(master):
    statements = [deepcopy(master['statements'][c['cve']]) for c in master['cases']]
    if master.get('evidence_reviews'):
        from src.web_evidence_review import apply
        statements = apply(master, statements, STORE.get('plan', master.get('operational_plan_id','')))
    n = len(statements)
    counts = dict(Counter(s['status'] for s in statements))
    deferred = counts.get('under_investigation', 0)
    out = {'schema': 'ics-vex-item4-review/5', 'review_id': master['id'],
           'arm': 'operational-context', 'statements': statements, 'total': n,
           'by_status': counts, 'deferred': deferred,
           'deferral_rate': deferred / n if n else 0,
           'decision_rate': 1 - deferred / n if n else 0,
           'routes': {c['cve']: deepcopy(c['analysis_route']) for c in master['cases']},
           'pipeline': {'name': 'Operational-context VEX review', 'case_count': n,
                        'model_eligible_cases': n,
                        'complete_cases': sum(bool(s.get('pipeline_complete')) for s in statements),
                        'extraction_status': dict(Counter(s['extraction']['status'] for s in statements)),
                        'authoring_status': dict(Counter(s['authoring']['status'] for s in statements)),
                        'stages': ['operational_questions', 'operational_evidence_review',
                                   'locked_vex_decision', 'validated_export'],
                        'answer_key_used': False, 'review_required': True},
           'vex_drafts': [s['document_draft'] for s in statements if s.get('document_draft')],
           'component_facts': deepcopy(master.get('component_facts', {})),
           'operational_context': deepcopy(master.get('operational_context', {})),
           'evidence_history': deepcopy(master.get('history', [])),
           'evidence_reviews': deepcopy(master.get('evidence_reviews', {})),
           'evidence_revisions': deepcopy(master.get('evidence_revisions', [])),
           'attachments': list(deepcopy(master.get('attachments', {})).values())}
    out['current_asset_scopes'] = deepcopy(master.get('current_asset_scopes', {}))
    out['review_cases'] = [{k:deepcopy(c[k]) for k in ('cve','component','version','description','vector','mappings') if k in c} for c in master['cases']]
    out['input_sbom'] = deepcopy(master.get('sbom'))
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
              'simulation': simulation, 'sbom': deepcopy(sbom), 'cases': [],
              'statements': {}, 'history': [], 'policy_version': VERSION}
    for original in cases:
        c = deepcopy(original)
        c['analysis_route'] = classify(c)
        c['case_id'] = master['id'] + ':' + c['cve']
        master['cases'].append(c)
        reason = 'Operating context, component version records and CVE-specific answers are pending.'
        master['statements'][c['cve']] = {
            'cve': c['cve'], 'case_id': c['case_id'], 'status': 'under_investigation',
            'justification': None, 'reason': reason, 'arm': 'operational-context',
            'scope': 'Operational-context review pending', 'analysis_route': c['analysis_route'],
            'extraction': {'status': 'not_run', 'usable': False},
            'authoring': {'status': 'not_run', 'prediction': None, 'reason': reason},
            'document_draft': None, 'pipeline_complete': False, 'review_required': True,
            'evidence_progress': {'operational': False, 'ready_for_authoring': False, 'pending': [reason]},
            'missing': [{'requirement': reason}]}
    STORE.put('item4_review', master['id'], master, TTL)
    return result(master)


def questions(review_id):
    with _lock:
        master = get(review_id)
        if master.get('operational_plan_id'):
            plan = STORE.get('plan', master['operational_plan_id'])
            from src.fixed_operational_questions import signature
            if plan and plan.get('question_generator_signature') == signature():
                return {**OQ.public(plan), 'review_id': review_id,
                        'routes': {c['cve']: c['analysis_route'] for c in master['cases']}}
        plan = OQ.create(master['cases'], master['product'], review_id, master['simulation'],
                         sbom=master.get('sbom'), question_role='fixed-operational-templates')
        master['operational_plan_id'] = plan['id']
        STORE.put('item4_review', review_id, master, TTL)
        return {**plan, 'review_id': review_id,
                'routes': {c['cve']: c['analysis_route'] for c in master['cases']}}


def generate_tuned_question_case(review_id, cve):
    raise ValueError('The primary review uses fixed workflow templates; model question generation is disabled.')


def save_evidence(review_id, plan_id, raw_case):
    from src import web_evidence_review as E
    with _lock:
        master = get(review_id)
        if plan_id != master.get('operational_plan_id'):
            raise ValueError('Evidence belongs to an older or different questionnaire. Reopen the current plan.')
        plan = STORE.get('plan', plan_id)
        if not plan:
            raise KeyError('Questionnaire expired; prepare it again.')
        case, question_plan = E.validate_case(plan, raw_case)
        cve, ref = case['binding']['cve'], case['binding']['asset_ref']
        fact = master.get('component_facts', {}).get(ref, {})
        if fact.get('attested') and fact.get('evidence'):
            if fact.get('installed_version') and fact['installed_version'] != case['binding']['build']:
                raise ValueError('Evidence build conflicts with saved installed-version facts. Reconcile the installed facts first.')
            if fact.get('product_name') and fact['product_name'] != case['binding']['product']:
                raise ValueError('Evidence product conflicts with saved component facts. Reconcile the product identity first.')
        E.evaluate_entry(question_plan, case, master.get('attachments', {}), review_id)
        previous = master.get('evidence_reviews', {}).get(cve, {}).get(ref)
        if previous:
            master.setdefault('evidence_revisions', []).append({'cve':cve,'asset_ref':ref,**deepcopy(previous)})
            master['evidence_revisions'] = master['evidence_revisions'][-20:]
        master.setdefault('evidence_reviews', {}).setdefault(cve, {})[ref] = {
            'case':case, 'question_plan':question_plan, 'plan_id':plan_id,
            'saved_at':E.now(), 'sha256':VR.fingerprint(case)}
        master.setdefault('current_asset_scopes', {})[ref] = {k:case['binding'][k] for k in ('product','build','config_baseline','mode')}
        master['history'].append({'cve':cve, 'asset_ref':ref, 'evidence_kind':'scoped_evidence',
                                  'sha256':VR.fingerprint(case), 'recorded_at':time.time()})
        STORE.put('item4_review', review_id, master, TTL)
        return result(master)


def add_attachment(review_id, cve, asset_ref, filename, content):
    from src import web_evidence_review as E
    import hashlib
    with _lock:
        master = get(review_id)
        plan = STORE.get('plan', master.get('operational_plan_id',''))
        if not plan or asset_ref not in {a['ref'] for a in E.assets_for(plan, cve)}:
            raise ValueError('Prepare this CVE/asset questionnaire before adding evidence files.')
        if not content or len(content) > 5*1024*1024:
            raise ValueError('Evidence file must be nonempty and at most 5 MiB.')
        if len(master.get('attachments', {})) >= 100:
            raise ValueError('This review already has 100 evidence files.')
        attachment = {'id':uuid.uuid4().hex, 'cve':cve, 'asset_ref':asset_ref,
            'filename':str(filename or 'evidence').replace('\\','/').split('/')[-1][:200],
            'sha256':hashlib.sha256(content).hexdigest(), 'bytes':len(content), 'uploaded_at':E.now()}
        path = E.attachment_path(review_id, attachment)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        master.setdefault('attachments', {})[attachment['id']] = attachment
        STORE.put('item4_review', review_id, master, TTL)
        return attachment


def attachment(review_id, file_id):
    from src import web_evidence_review as E
    master = get(review_id)
    record = master.get('attachments', {}).get(file_id)
    if not record:
        raise KeyError('Evidence file not found in this review.')
    path = E.attachment_path(review_id, record)
    if not path.is_file() or E.file_hash(path) != record['sha256']:
        raise ValueError('Evidence file is missing or its SHA-256 does not match.')
    return record, path


def export_evidence(review_id, format):
    from src.web_evidence_review import exports
    from src.web_evidence_review import now
    with _lock:
        master = get(review_id)
        master['export_revision'] = master.get('export_revision', 0)+1
        master.setdefault('initial_export_at', now())
        document = exports(result(master), master, format)
        STORE.put('item4_review', review_id, master, TTL)
        return document


def answers(review_id, values, component_facts=None, *, plan_id=None, operational_context=None):
    with _lock:
        master = get(review_id)
        if not master.get('operational_plan_id'):
            raise ValueError('Generate operational questions for this review first.')
        if plan_id is not None and plan_id != master['operational_plan_id']:
            raise ValueError('Questionnaire does not belong to the current review plan. Reopen the form.')
        kwargs = {'operational_context': operational_context} if operational_context is not None else {}
        assessed = OQ.assess(master['operational_plan_id'], values, component_facts, author=False, **kwargs)
        master['component_facts'] = assessed.get('component_facts', {})
        master['operational_context'] = assessed.get('operational_context', {})
        known = {c['cve']: c for c in master['cases']}
        statements = assessed['statements']
        if len({s['cve'] for s in statements}) != len(statements) or any(s['cve'] not in known for s in statements):
            raise ValueError('Result contains a CVE outside this review.')
        for s in statements:
            c = known[s['cve']]
            s['analysis_route'] = deepcopy(c['analysis_route'])
            s['case_id'] = c['case_id']
            s['evidence_progress'] = {'operational': True, 'ready_for_authoring': True, 'pending': []}
            signature = VR.fingerprint(s)
            if master['statements'][c['cve']].get('authoring_evidence_sha256') == signature:
                continue
            prepared = VR.prepare([c], product=master['product'], run_id=master['id'], simulation=master['simulation'])
            finished = VR.finish({'statements': [s]}, prepared)['statements'][0]
            finished['authoring_evidence_sha256'] = signature
            master['statements'][c['cve']] = finished
            master['history'].append({'cve': c['cve'], 'case_id': c['case_id'],
                                      'evidence_kind': 'operational', 'sha256': signature,
                                      'recorded_at': time.time()})
        STORE.put('item4_review', review_id, master, TTL)
        return result(master)
