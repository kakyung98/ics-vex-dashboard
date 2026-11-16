"""Offline review gate. Reviewed evidence is an input assertion, not authentication.

No CVSS/CWE membership, yes/no answer, or external mitigation can clear a CVE.
This module deliberately does not call the legacy oc_vex_judge.
"""
from datetime import datetime, timezone

BINDING = ('cve', 'asset_ref', 'product', 'build', 'config_baseline', 'mode')
JUSTIFICATIONS = {'component_not_present', 'vulnerable_code_not_present',
                  'vulnerable_code_not_in_execute_path',
                  'vulnerable_code_cannot_be_controlled_by_adversary',
                  'inline_mitigations_already_exist'}
PATH_JUSTIFICATIONS = {'vulnerable_code_not_in_execute_path',
                       'vulnerable_code_cannot_be_controlled_by_adversary'}


def instant(value):
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (ValueError, AttributeError, TypeError):
        return None


def evaluate(plan, case):
    """Evaluate ONE bound CVE/asset/mode; never execute unreviewed formulas.

    Evidence must contain ID, kind, source, quote, reviewer, observed_at,
    reviewed_at, valid_until, and the exact CVE/asset/product/build/config/mode.
    Clients must authenticate reviewers and preserve source integrity separately.
    """
    binding = case.get('binding') or {}
    result = {'cve': plan['cve'], 'status': 'under_investigation', 'justification': None,
              'operational_assessment': 'unknown', 'flow_assessments': [],
              'accepted_evidence_ids': [], 'missing_evidence': [], 'rejected_claims': [],
              'decision_policy': 'evidence_proofs_v3', 'binding': binding,
              'proofs': [], 'decision_trace': [], 'evidence_graph': {'nodes':[], 'edges':[]},
              'reason': '검토된 제품 영향·수정·비영향 근거가 부족하다.'}
    if binding.get('cve') != plan['cve'] or any(not isinstance(binding.get(k), str) or
            not binding[k].strip() or binding[k].casefold() in {'unknown', '미확인'} for k in BINDING):
        result['missing_evidence'].append('Complete matching CVE/asset/product/build/config/mode binding')
        return result
    evaluated = instant(binding.get('evaluated_at'))
    if evaluated is None:
        result['missing_evidence'].append('Timezone-aware evaluated_at')
        return result
    records = case.get('evidence', [])
    ids = [r.get('id') for r in records]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        result['missing_evidence'].append('Unique nonempty evidence IDs')
        return result
    byid = {r['id']: r for r in records}

    def evidence(ids, kinds=None):
        if not isinstance(ids, list) or not ids:
            return None
        selected = []
        for eid in ids:
            if eid in case.get('excluded_evidence_ids', []):
                return None
            r = byid.get(eid) if isinstance(eid, str) else None
            if not r or any(not isinstance(r.get(k), str) or not r[k].strip()
                            for k in ('kind', 'source', 'quote', 'reviewer')):
                return None
            if any((r.get('binding') or {}).get(k) != binding[k] for k in BINDING):
                return None
            observed, reviewed, expiry = [instant(r.get(k)) for k in ('observed_at', 'reviewed_at', 'valid_until')]
            if None in (observed, reviewed, expiry) or not observed <= reviewed <= evaluated <= expiry:
                return None
            selected.append(r)
        if kinds and not set(kinds) <= {r['kind'] for r in selected}:
            return None
        return selected

    question_ids = {q['id'] for q in plan['questions']}
    answered = set()
    for answer in case.get('answers', []):
        qid = answer.get('question_id')
        value = answer.get('value')
        if qid in question_ids and isinstance(value, str) and value.strip() and value not in {'unknown', '모름'} and evidence(answer.get('evidence_ids')):
            answered.add(qid)
    result['unanswered_question_ids'] = sorted(question_ids-answered)
    flows = sorted({q['flow'] for q in plan['questions'] if q['flow'] not in {'common', 'facet'}})
    for flow in flows:
        facts = [f for f in case.get('path_facts', []) if f.get('flow') == flow]
        states = []
        for fact in facts:
            checked = evidence(fact.get('evidence_ids'), {'operational_path_record'})
            if checked and fact.get('access') in {'reachable', 'blocked', 'mitigated'}:
                states.append(fact['access'])
        # One blocked path never establishes exhaustive path coverage.
        state = 'exposed' if 'reachable' in states else 'restricted_observed_paths' if 'blocked' in states else 'mitigated_observed_paths' if states else 'unknown'
        result['flow_assessments'].append({'flow': flow, 'state': state, 'coverage': 'observed_records_only'})
    states = [f['state'] for f in result['flow_assessments']]
    result['operational_assessment'] = 'exposed' if 'exposed' in states else 'unknown' if not states or 'unknown' in states else 'restricted_observed_paths' if all(s == 'restricted_observed_paths' for s in states) else 'partially_mitigated_observed_paths'

    if case.get('source_record_status') == 'Rejected' or any(q['flow'] == 'rejected_review' for q in plan['questions']):
        result['missing_evidence'].append('Resolve rejected CVE identity and replacement before adjudication')
        return result
    candidates = []
    findings = list(case.get('product_findings', []))
    # The primary UI records source assertions, not a user-selected final status.
    # Only reviewed source assertions can start an automatic proof candidate.
    if case.get('auto_findings'):
        context = case.get('decision_context') or {}
        supporting = [r['id'] for r in records if r.get('kind') in
                      {'installation_record', 'running_build_record'} and evidence([r['id']])]
        for r in records:
            if r.get('kind') not in {'supplier_product_status','reviewed_product_analysis','supplier_fix_mapping'}:
                continue
            status = r.get('asserted_status')
            if status not in {'affected','fixed','not_affected'}:
                continue
            refs = [r['id']]+(supporting if status == 'fixed' else [])
            findings.append({'status':status, 'evidence_ids':refs, 'origin':'source_assertion',
                'action_statement':context.get('action_statement', ''),
                'justification':context.get('justification'),
                'impact_statement':context.get('impact_statement', '')})
    for index, finding in enumerate(findings):
        status = finding.get('status')
        selected = evidence(finding.get('evidence_ids'))
        kinds = {r['kind'] for r in selected} if selected else set()
        valid = bool(selected) and status in {'fixed', 'affected', 'not_affected'}
        if status == 'fixed':
            valid = valid and {'supplier_fix_mapping', 'installation_record'} <= kinds
            valid = valid and ('running_build_record' in kinds or any(
                r.get('kind') == 'installation_record' and r.get('execution_verified') is True
                for r in selected or []))
        else:
            valid = valid and bool(kinds & {'supplier_product_status', 'reviewed_product_analysis'})
        # Product evidence must actually assert this status, not merely be a URL or version list.
        assertion_kinds = {'supplier_fix_mapping'} if status == 'fixed' else {'supplier_product_status', 'reviewed_product_analysis'}
        asserting = [r for r in selected or [] if r['kind'] in assertion_kinds]
        valid = valid and any(r.get('asserted_status') == status for r in asserting)
        if status == 'not_affected':
            valid = valid and (finding.get('justification') in JUSTIFICATIONS or bool(str(finding.get('impact_statement') or '').strip()))
            if finding.get('justification') is not None and finding['justification'] not in JUSTIFICATIONS:
                valid = False
        if status == 'affected':
            valid = valid and bool(str(finding.get('action_statement') or '').strip())
        rule = {'fixed':'F:fix_and_active_deployment', 'affected':'A:reviewed_product_impact',
                'not_affected':'N:reviewed_product_nonimpact'}.get(status, 'invalid_claim')
        proof = {'id':'proof-'+str(index+1), 'status':status, 'rule':rule,
                 'supported':bool(valid), 'evidence_ids':finding.get('evidence_ids', []),
                 'origin':finding.get('origin','reviewed_finding')}
        if not valid:
            proof['missing'] = ('CVE-specific fix mapping, installation and active running-build confirmation'
                if status == 'fixed' else 'A scoped reviewed assertion and action or non-impact explanation')
        result['proofs'].append(proof)
        if valid:
            candidates.append({**finding, 'proof_id':proof['id']})
        else:
            result['rejected_claims'].append({'claim': status, 'reason': 'Missing, unreviewed, stale, out-of-scope or semantically mismatched evidence'})

    path = case.get('path_analysis') or {}
    # Exhaustiveness and necessity are reviewed CVE-specific inputs, never inferred from labels.
    coverage = path.get('coverage_complete') is True and evidence(path.get('evidence_ids'), {'reviewed_complete_route_analysis'})
    if coverage and path.get('routes'):
        refutations = []
        route_ids = [r.get('id') for r in path['routes']]
        valid_routes = all(isinstance(i, str) and i for i in route_ids) and len(set(route_ids)) == len(route_ids)
        for route in path['routes']:
            blockers = []
            for cond in route.get('conditions', []):
                if (cond.get('question_id') in question_ids and cond.get('necessary') is True and
                    cond.get('fact') == 'no' and cond.get('justification') in PATH_JUSTIFICATIONS and
                    evidence(cond.get('evidence_ids'), {'reviewed_cve_prerequisite', 'reviewed_nonexecution_analysis'})):
                    blockers.append(cond)
            if not blockers:
                valid_routes = False
            else:
                refutations.append(blockers[0])
        if valid_routes:
            justs = {c['justification'] for c in refutations}
            candidates.append({'status': 'not_affected',
                               'justification': next(iter(justs)) if len(justs) == 1 else None,
                               'impact_statement': '검토된 모든 대체 경로에서 필수 조건의 구조적 불성립이 확인되었다.',
                               'evidence_ids': list(dict.fromkeys(path['evidence_ids']+[i for c in refutations for i in c['evidence_ids']]))})
            result['proofs'].append({'id':'proof-routes', 'status':'not_affected',
                'rule':'N:all_reviewed_alternative_routes_refuted', 'supported':True,
                'evidence_ids':candidates[-1]['evidence_ids']})
        else:
            result['missing_evidence'].append('A reviewed structural refutation for EACH alternative route')
    elif path:
        result['missing_evidence'].append('Reviewed exhaustive CVE-specific route analysis')

    statuses = {c['status'] for c in candidates}
    if len(statuses) > 1:
        result['reason'] = '동일 대상과 현재 범위에서 유효한 판정 근거가 충돌한다.'
        result['missing_evidence'].append('Resolve conflicting valid product proofs for the same current scope')
    elif candidates:
        chosen = candidates[0]
        result.update(status=chosen['status'], justification=chosen.get('justification'),
                      impact_statement=chosen.get('impact_statement'), action_statement=chosen.get('action_statement'),
                      accepted_evidence_ids=sorted({i for c in candidates for i in c['evidence_ids']}),
                       reason='동일 CVE·제품·빌드·구성·모드의 유효한 검토 근거를 적용했다.')
    else:
        result['missing_evidence'].append('Reviewed supplier/product decision or complete structural route refutation')
    result['decision_trace'] = [
        {'check':'scope', 'outcome':'matched', 'detail':'CVE, asset, product, build, configuration, mode and evaluation time bound'},
        {'check':'proofs', 'outcome':'conflict' if len(statuses)>1 else 'supported' if candidates else 'insufficient',
         'proof_ids':[p['id'] for p in result['proofs'] if p['supported']]},
        {'check':'decision', 'outcome':result['status'], 'evidence_ids':result['accepted_evidence_ids']},
    ]
    # Rejected/expired side claims are visible, but cannot erase a valid impact proof.
    result['next_steps'] = ([] if candidates and len(statuses)==1 else
        list(dict.fromkeys(result['missing_evidence']+[p['missing'] for p in result['proofs'] if not p['supported']])))
    result['remaining_answers_block_decision'] = result['status'] == 'under_investigation'
    nodes = [{'id':'scope', 'kind':'assessment_scope', 'label':binding.get('asset_ref',''), 'binding':binding},
             {'id':'build', 'kind':'installed_build', 'label':binding.get('build','')},
             {'id':'cve', 'kind':'vulnerability', 'label':plan['cve']},
             {'id':'decision', 'kind':'vex_statement', 'label':result['status']}]
    edges = [{'from':'scope','to':'cve','relation':'assessed_against'},
             {'from':'scope','to':'build','relation':'assessment_build'}]
    for r in records:
        node = 'evidence:'+r['id']
        nodes.append({'id':node,'kind':'evidence','label':r['id'],'source':r.get('source'),
                      'quote':r.get('quote'), 'reviewer':r.get('reviewer'),
                      'usable_for_decision':bool(evidence([r['id']]))})
        edges.append({'from':node,'to':'scope','relation':'declared_scope'})
    for q in plan['questions']:
        node = 'question:'+q['id']
        nodes.append({'id':node,'kind':'review_question','label':q.get('question',q['id']),
                      'source_refs':q.get('evidence_ids',[]), 'necessity':q.get('necessity','not_established')})
        edges.append({'from':'cve','to':node,'relation':'selects_review_question'})
    for answer in case.get('answers', []):
        node = 'answer:'+answer['question_id']
        nodes.append({'id':node,'kind':'reported_fact','label':answer.get('value','unknown')})
        edges.append({'from':node,'to':'question:'+answer['question_id'],'relation':'reports_answer'})
        for ref in answer.get('evidence_ids',[]):
            edges.append({'from':'evidence:'+ref,'to':node,'relation':'submitted_support'})
    for p in result['proofs']:
        nodes.append({'id':p['id'],'kind':'proof','label':p['rule'],'supported':p['supported']})
        for ref in p['evidence_ids']:
            edges.append({'from':'evidence:'+ref,'to':p['id'],'relation':'supports' if p['supported'] else 'submitted_for'})
        edges.append({'from':p['id'],'to':'decision','relation':'decision_basis' if p['supported'] and p['status']==result['status'] else 'reviewed_candidate'})
    result['evidence_graph'] = {'nodes':nodes,'edges':edges,
        'boundary':'Source-linked human-reviewed assertions; graph structure is not independent proof of source truth.'}
    return result
