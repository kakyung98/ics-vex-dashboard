"""Bound evidence review shared by the website, persistence and exporters.

Reviewer identity and source interpretation remain explicit human attestations.
The gate verifies structure, scope, dates and evidence categories, not source truth.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid
from src import operational_evidence_judge as JUDGE

ROOT = Path(__file__).resolve().parents[1]
ATTACHMENTS = ROOT/'results/review_attachments'
KINDS = {
    'supplier_product_status': 'Supplier product impact statement',
    'reviewed_product_analysis': 'Reviewed product analysis',
    'supplier_fix_mapping': 'Supplier CVE-to-fix mapping',
    'installation_record': 'Installed build or update record',
    'running_build_record': 'Active running build after required restart or activation',
    'operational_path_record': 'Observed access path or enforced control',
    'reviewed_complete_route_analysis': 'Reviewed complete set of alternative paths',
    'reviewed_cve_prerequisite': 'Reviewed CVE-specific necessary condition',
    'reviewed_nonexecution_analysis': 'Reviewed structural non-execution/control proof',
}
STATUSES = {'affected', 'fixed', 'not_affected', 'under_investigation'}


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def assets_for(plan, cve):
    row = next((r for r in plan['cases'] if r['case']['cve'] == cve), None)
    if row is None:
        raise ValueError('CVE is outside this questionnaire')
    refs = {str(m.get('component_id') or 'asset') for m in row['case'].get('mappings', [])}
    return [a for a in plan['assets'] if not refs or a['ref'] in refs]


def question_plan(plan, cve):
    row = next((r for r in plan['cases'] if r['case']['cve'] == cve), None)
    if row is None:
        raise ValueError('CVE is outside this questionnaire')
    return {'cve': cve, 'questions': [{**deepcopy(q), 'flow': q.get('flow', 'common')}
                                    for q in row['questions']]}


def _object(value, keys, name):
    if not isinstance(value, dict) or set(value)-set(keys):
        raise ValueError('Invalid '+name+' fields')


def _text(value, limit, name):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError('Invalid '+name)


def _list(value, limit, name):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError('Invalid '+name)


def _refs(value):
    _list(value, 40, 'evidence references')
    if not all(isinstance(x, str) and 0 < len(x) <= 120 for x in value):
        raise ValueError('Invalid evidence reference')


def validate_case(plan, raw):
    """Reject malformed/cross-plan data. Incomplete evidence may be saved as unknown."""
    _object(raw, {'binding','evidence','answers','path_facts','product_findings','path_analysis',
                  'auto_findings','decision_context'}, 'case')
    case = deepcopy(raw)
    if type(case.get('auto_findings', False)) is not bool:
        raise ValueError('Automatic proof assembly must be a boolean')
    context = case.get('decision_context', {})
    _object(context, {'action_statement','impact_statement','justification'}, 'decision context')
    for field in ('action_statement','impact_statement'):
        _text(context.get(field, ''), 4000, field)
    if context.get('justification') not in {None, '', *JUDGE.JUSTIFICATIONS}:
        raise ValueError('Invalid non-impact justification')
    binding = case.get('binding', {})
    _object(binding, {*JUDGE.BINDING, 'evaluated_at'}, 'binding')
    for key in JUDGE.BINDING:
        _text(binding.get(key, ''), 500 if key == 'product' else 200, key)
    cve = binding.get('cve')
    expected = {a['ref'] for a in assets_for(plan, cve)}
    if binding.get('asset_ref') not in expected:
        raise ValueError('Asset is outside this CVE questionnaire')
    binding['evaluated_at'] = now()  # Clients cannot backdate an expiry check.
    qp = question_plan(plan, cve)
    questions = {q['id']: q for q in qp['questions']}
    flows = {q['flow'] for q in qp['questions'] if q['flow'] not in {'common', 'facet'}}
    records = case.setdefault('evidence', [])
    _list(records, 40, 'evidence records')
    ids = []
    for record in records:
        _object(record, {'id','kind','source','quote','reviewer','observed_at','reviewed_at','valid_until',
                          'binding','asserted_status','question_ids','attachment_id','execution_verified'}, 'evidence record')
        if 'execution_verified' in record and type(record['execution_verified']) is not bool:
            raise ValueError('Running-build confirmation must be a boolean')
        for field, limit in [('id',120),('kind',100),('source',2000),('quote',6000),('reviewer',200),
                             ('observed_at',80),('reviewed_at',80),('valid_until',80)]:
            _text(record.get(field, ''), limit, field)
        if not record.get('id') or record.get('kind') not in KINDS:
            raise ValueError('Evidence ID and supported evidence kind are required')
        ids.append(record['id'])
        _object(record.get('binding', {}), JUDGE.BINDING, 'evidence binding')
        for field in JUDGE.BINDING:
            _text(record.get('binding', {}).get(field, ''), 500, 'evidence '+field)
        if record.get('asserted_status') is not None:
            _text(record['asserted_status'], 80, 'asserted product status')
        if record.get('asserted_status') not in {None, '', *STATUSES}:
            raise ValueError('Invalid asserted product status')
        question_ids = record.get('question_ids', [])
        _list(question_ids, 50, 'linked questions')
        if any(not isinstance(q, str) or q not in questions for q in question_ids):
            raise ValueError('Evidence links a question outside this CVE plan')
        if record.get('attachment_id') is not None and not re.fullmatch(r'[a-f0-9]{32}', str(record['attachment_id'])):
            raise ValueError('Invalid attachment identifier')
    if len(set(ids)) != len(ids):
        raise ValueError('Evidence IDs must be unique')
    _list(case.setdefault('answers', []), 100, 'answers')
    for answer in case['answers']:
        _object(answer, {'question_id','value','evidence_ids'}, 'answer')
        if not isinstance(answer.get('question_id'), str) or answer['question_id'] not in questions or not isinstance(answer.get('value'), str) or len(answer['value']) > 500:
            raise ValueError('Invalid question answer')
        if questions[answer['question_id']].get('answer_type') != 'text' and answer['value'] not in {'yes','no','unknown'}:
            raise ValueError('Use yes, no or unknown for this question')
        _refs(answer.get('evidence_ids', []))
    _list(case.setdefault('path_facts', []), 30, 'path facts')
    for fact in case['path_facts']:
        _object(fact, {'flow','access','evidence_ids'}, 'path fact')
        if not isinstance(fact.get('flow'), str) or fact['flow'] not in flows or not isinstance(fact.get('access'), str) or fact['access'] not in {'reachable','blocked','mitigated','unknown'}:
            raise ValueError('Invalid flow observation')
        _refs(fact.get('evidence_ids', []))
    _list(case['path_facts'], 30, 'path facts')
    findings = case.setdefault('product_findings', [])
    _list(findings, 20, 'product findings')
    for finding in findings:
        _object(finding, {'status','evidence_ids','justification','impact_statement','action_statement'}, 'product finding')
        if not isinstance(finding.get('status'), str) or finding['status'] not in {'fixed','affected','not_affected'}:
            raise ValueError('Invalid product finding status')
        if finding.get('justification') is not None:
            _text(finding['justification'], 100, 'justification')
        if finding.get('justification') not in {None, '', *JUDGE.JUSTIFICATIONS}:
            raise ValueError('Invalid non-impact justification')
        if finding.get('justification') == '':
            finding['justification'] = None
        for field in ('impact_statement','action_statement'):
            _text(finding.get(field, ''), 4000, field)
        _refs(finding.get('evidence_ids', []))
    path = case.setdefault('path_analysis', {})
    _object(path, {'coverage_complete','evidence_ids','routes'}, 'path analysis')
    if path:
        if type(path.get('coverage_complete', False)) is not bool:
            raise ValueError('Path coverage must be a boolean')
        _refs(path.get('evidence_ids', []))
        routes = path.get('routes', [])
        _list(routes, 20, 'alternative routes')
        for route in routes:
            _object(route, {'id','conditions'}, 'alternative route')
            _text(route.get('id'), 200, 'route name')
            _list(route.get('conditions', []), 30, 'route conditions')
            for cond in route.get('conditions', []):
                _object(cond, {'id','question_id','condition_text','necessary','fact','evidence_ids','justification'}, 'condition')
                _text(cond.get('id', ''), 120, 'condition identifier')
                _text(cond.get('condition_text', ''), 2000, 'CVE-specific condition')
                if not cond.get('condition_text', '').strip():
                    raise ValueError('Describe the CVE-specific prerequisite; a checklist answer alone is not a condition')
                q = questions.get(cond.get('question_id')) if isinstance(cond.get('question_id'), str) else None
                if not q or q.get('purpose_category') in {'operational_impact','mitigation','product_evidence'} or q.get('origin') == 'system':
                    raise ValueError('Select an operational condition question; impact/recovery/patch checks cannot refute a route')
                if type(cond.get('necessary')) is not bool or not isinstance(cond.get('fact'), str) or cond['fact'] not in {'yes','no','unknown'}:
                    raise ValueError('Invalid necessity or condition fact')
                if not isinstance(cond.get('justification'), str) or cond['justification'] not in JUDGE.PATH_JUSTIFICATIONS:
                    raise ValueError('Invalid structural refutation justification')
                _refs(cond.get('evidence_ids', []))
    known_ids = set(ids)
    referenced = [x for a in case['answers'] for x in a.get('evidence_ids', [])]
    referenced += [x for f in case['path_facts']+findings for x in f.get('evidence_ids', [])]
    referenced += path.get('evidence_ids', [])
    referenced += [x for r in path.get('routes', []) for c in r.get('conditions', []) for x in c.get('evidence_ids', [])]
    if set(referenced)-known_ids:
        raise ValueError('An evidence reference is not registered in this asset review')
    return case, qp


def attachment_path(review_id, attachment):
    if not re.fullmatch(r'[a-f0-9]{32}', review_id) or not re.fullmatch(r'[a-f0-9]{32}', attachment['id']):
        raise ValueError('Invalid attachment path identifier')
    root = ATTACHMENTS.resolve()
    path = (root/review_id/(attachment['id']+'.bin')).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Attachment path is outside storage')
    return path


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def evaluate_entry(plan, case, attachments, review_id):
    report = []
    for r in case['evidence']:
        issues = []
        if any(not str(r.get(k) or '').strip() for k in ('source','quote','reviewer')):
            issues.append('Source, passage and reviewer are required')
        if any(r.get('binding', {}).get(k) != case['binding'].get(k) for k in JUDGE.BINDING):
            issues.append('Evidence scope differs from the assessed asset/build/configuration/mode')
        dates = [JUDGE.instant(r.get(k)) for k in ('observed_at','reviewed_at','valid_until')]
        at = JUDGE.instant(case['binding']['evaluated_at'])
        if None in dates or not dates[0] <= dates[1] <= at <= dates[2]:
            issues.append('Missing, future, expired or unordered evidence timestamps')
        if r.get('attachment_id'):
            attachment = attachments.get(r['attachment_id'])
            if not attachment or attachment['cve'] != case['binding']['cve'] or attachment['asset_ref'] != case['binding']['asset_ref']:
                issues.append('Attachment belongs to another review asset or CVE')
            else:
                path = attachment_path(review_id, attachment)
                try:
                    valid_file = path.is_file() and file_hash(path) == attachment['sha256']
                except OSError:
                    valid_file = False
                if not valid_file:
                    issues.append('Attachment is missing or its SHA-256 has changed')
        report.append({'id':r['id'], 'valid':not issues, 'issues':issues})
    checked_case = {**case, 'excluded_evidence_ids':[r['id'] for r in report if not r['valid']]}
    result = JUDGE.evaluate(plan, checked_case)
    result['evidence_validation'] = report
    if checked_case['excluded_evidence_ids']:
        result['record_warnings'] = ['Excluded invalid records: '+', '.join(checked_case['excluded_evidence_ids'])]
        if result['status'] == 'under_investigation':
            result['missing_evidence'].append('Resolve invalid evidence records shown in the validation report')
    result['reviewer_verification'] = 'Human review declarations; reviewer identity and source truth are not automatically authenticated.'
    return result


def apply(master, statements, plan):
    """Re-evaluate expiry at read/export time; preserve per-asset decisions."""
    bycve = {s['cve']:s for s in statements}
    for cve, entries in master.get('evidence_reviews', {}).items():
        statement = bycve[cve]
        expected = {a['ref']:a for a in assets_for(plan, cve)} if plan else {r: {} for r in entries}
        components = []
        for ref, asset in expected.items():
            entry = entries.get(ref)
            if not entry or not plan or entry['plan_id'] != master.get('operational_plan_id'):
                components.append({'asset_ref':ref,'status':'under_investigation','justification':None,
                    'reason':'No current evidence review for this component/question plan.', 'accepted_evidence_ids':[]})
                continue
            case = deepcopy(entry['case']);case['binding']['evaluated_at'] = now()
            assessed = evaluate_entry(entry['question_plan'], case, master.get('attachments', {}), master['id'])
            current = master.get('current_asset_scopes', {}).get(ref, {})
            fact = master.get('component_facts', {}).get(ref, {})
            mismatch = any(case['binding'].get(k) != v for k,v in current.items())
            if fact.get('attested') and fact.get('evidence'):
                mismatch |= bool(fact.get('installed_version') and fact['installed_version'] != case['binding']['build'])
                mismatch |= bool(fact.get('product_name') and fact['product_name'] != case['binding']['product'])
            if mismatch:
                assessed.update(status='under_investigation', justification=None, accepted_evidence_ids=[],
                                reason='The current asset identity/build/configuration/mode differs from this saved evidence scope.')
                assessed['missing_evidence'].append('Reassess this CVE against the current installed asset scope')
                assessed['current_asset_scope'] = deepcopy(current)
            assessed['asset_ref'] = ref
            components.append(assessed)
        statuses = {c['status'] for c in components}
        status = ('affected' if 'affected' in statuses else 'under_investigation' if 'under_investigation' in statuses or not statuses
                  else 'fixed' if statuses == {'fixed'} else 'not_affected')
        justifications = {c.get('justification') for c in components}
        justification = next(iter(justifications)) if status == 'not_affected' and len(justifications) == 1 else None
        reason = ' / '.join(c['asset_ref']+': '+c['reason'] for c in components)
        action = ' / '.join(c.get('action_statement') or '' for c in components if c['status'] == 'affected').strip(' /')
        evidence_ids = sorted({i for c in components for i in c.get('accepted_evidence_ids', [])})
        statement.update(status=status, justification=justification, reason=reason,
            scope='Evidence-bound asset/build/configuration/mode; component-specific results retained',
            evidence_decision={'policy':'evidence_proofs_v3','components':components,'evaluated_at':now()},
            authoring={'status':'validated_rules','method':'evidence_gate_template','llm_used':False},
            evidence_packet={'method':'reviewed_scoped_evidence_v2','locked_status':status,
                             'evidence_ids':evidence_ids,'model_called':False,
                             'claim_boundary':'Scoped human-reviewed declarations; source truth and reviewer identity are not automatically authenticated.'},
            document_draft={'cve':cve,'status':status,'justification':justification,
                            'impact_statement':reason,'action_statement':action or None,'evidence_refs':evidence_ids},
            pipeline_complete=True, review_required=True)
    return statements


def exports(review, master, format):
    """Canonical server exports use individual asset decisions, never the summary alone."""
    rows = []
    from src import review_store
    plan = review_store.get('plan', master.get('operational_plan_id',''))
    if not plan:
        raise ValueError('The questionnaire has expired. Reopen and prepare the review before exporting.')
    for s in review['statements']:
        components = s.get('evidence_decision', {}).get('components', [])
        if not components and plan:
            components = [{'asset_ref':a['ref'],'status':'under_investigation','justification':None,
                           'reason':'No structured, scoped evidence assessment for this CVE/component.',
                           'accepted_evidence_ids':[]} for a in assets_for(plan, s['cve'])]
        for r in components:
            binding = r.get('binding') or {'asset_ref':r['asset_ref'], 'product':r['asset_ref'], 'build':'unconfirmed'}
            pid = 'urn:ics-vex:scope:'+hashlib.sha256(json.dumps({k:v for k,v in binding.items() if k not in {'evaluated_at','cve'}}, sort_keys=True).encode()).hexdigest()[:24]
            rows.append((s['cve'],r,binding,pid))
    if not rows:
        raise ValueError('Save at least one evidence-based assessment before exporting')
    stamp = now()
    version = master.get('export_revision', 1)
    initial = master.get('initial_export_at', stamp)
    if format == 'openvex':
        statements = []
        for cve,r,b,pid in rows:
            item = {'vulnerability':{'name':cve},'products':[{'@id':pid}], 'status':r['status'],
                    'timestamp':stamp,'status_notes':r['reason']+' Scope: '+json.dumps(b,ensure_ascii=False)+' Evidence IDs: '+', '.join(r.get('accepted_evidence_ids', []))}
            if r['status'] == 'not_affected':
                if r.get('justification'):item['justification'] = r['justification']
                item['impact_statement'] = r.get('impact_statement') or r['reason']
            if r['status'] == 'affected':item['action_statement'] = r['action_statement']
            statements.append(item)
        return {'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:ics-vex:review:'+master['id'],
                'author':'ICS-VEXForge evidence review','role':'Document Creator','timestamp':stamp,
                'version':version, 'statements':statements}
    if format == 'cyclonedx':
        if not review.get('sbom_vex'):
            raise ValueError('CycloneDX export requires a bound CycloneDX input SBOM')
        document = deepcopy(review['sbom_vex'])
        document['version'] = int((master.get('sbom') or {}).get('version',1))+version
        return document
    if format != 'csaf':
        raise ValueError('Unsupported VEX export format')
    vulns = {}
    statusmap = {'affected':'known_affected','not_affected':'known_not_affected','fixed':'fixed','under_investigation':'under_investigation'}
    for cve,r,b,pid in rows:
        v = vulns.setdefault(cve, {'cve':cve,'product_status':{},'notes':[]})
        v['product_status'].setdefault(statusmap[r['status']], []).append(pid)
        v['notes'].append({'category':'description','title':b['asset_ref'], 'text':r['reason']+' Scope: '+json.dumps(b,ensure_ascii=False)})
        if r['status'] == 'not_affected':
            if r.get('justification'):v.setdefault('flags', []).append({'label':r['justification'],'product_ids':[pid]})
            v.setdefault('threats', []).append({'category':'impact','details':r.get('impact_statement') or r['reason'],'product_ids':[pid]})
        if r['status'] == 'affected':v.setdefault('remediations', []).append({'category':'mitigation','details':r['action_statement'],'product_ids':[pid]})
    return {'document':{'category':'csaf_vex','csaf_version':'2.0','title':'Evidence-bound VEX review',
            'publisher':{'category':'other','name':'ICS-VEXForge'},
            'tracking':{'id':master['id'],'status':'draft','version':str(version),
                        'initial_release_date':initial,'current_release_date':stamp,
                        'revision_history':([{'number':'1','date':initial,'summary':'Initial evidence export'}] if version != 1 else [])+
                                           [{'number':str(version),'date':stamp,'summary':'Current evidence validation'}]}},
            'product_tree':{'full_product_names':list({pid:{'product_id':pid,'name':b['product']+' '+b['build']+' ['+b['asset_ref']+']'} for _,_,b,pid in rows}.values())},
            'vulnerabilities':list(vulns.values())}
