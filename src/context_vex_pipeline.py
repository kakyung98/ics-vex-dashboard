"""Reviewed CVE formulas and scoped operator facts; clustering is never proof."""
import math
from datetime import datetime
from .operational_evidence_judge import BINDING, evaluate as evidence_judge, instant

VALUES = ('true', 'false', 'unknown')


def logic(node, facts, depth=0):
    if depth > 64 or not isinstance(node, dict):
        raise ValueError('Invalid or excessively deep formula')
    if set(node) == {'condition'}:
        return facts.get(node['condition'], 'unknown')
    op, args = node.get('op'), node.get('args')
    if set(node) != {'op', 'args'} or op not in ('and', 'or', 'not') or not isinstance(args, list) or not args:
        raise ValueError('Formula must contain condition or AND/OR/NOT with nonempty args')
    if op == 'not' and len(args) != 1:
        raise ValueError('NOT requires exactly one argument')
    values = [logic(a, facts, depth+1) for a in args]
    if op == 'not':
        return {'true': 'false', 'false': 'true', 'unknown': 'unknown'}[values[0]]
    decisive, neutral = ('false', 'true') if op == 'and' else ('true', 'false')
    return decisive if decisive in values else neutral if all(v == neutral for v in values) else 'unknown'


def leaves(node):
    logic(node, {})  # Validate before recursion.
    if 'condition' in node:
        return {node['condition']}
    return set().union(*(leaves(n) for n in node['args']))


def approved(item):
    return (item.get('validation_status') == 'approved' and
            bool(str(item.get('reviewer', '')).strip()) and instant(item.get('reviewed_at')) is not None)


def validate_review(review, record):
    """Check references, not the truth of the reviewer's semantic assertions."""
    if review['cve'] != record['cve']:
        raise ValueError('CVE mismatch')
    sources = {s['id']: s for s in record['sources']}
    def references(item):
        refs = item.get('source_refs', [])
        if not refs:
            raise ValueError('Reviewed assertion requires exact source spans')
        for ref in refs:
            source = sources[ref['source_id']]
            start, end = ref['span']
            if not (0 <= start < end <= len(source['text'])) or source['text'][start:end] != ref['quote']:
                raise ValueError('Source span mismatch')
    conditions = review.get('conditions', [])
    questions = review.get('questions', [])
    for rows in (conditions, questions):
        ids = [r['id'] for r in rows]
        if len(ids) != len(set(ids)) or any(not isinstance(i, str) or not i for i in ids):
            raise ValueError('IDs must be unique and nonempty')
    byid = {c['id']: c for c in conditions}
    for c in conditions:
        if not c.get('predicate') or not c.get('target'):
            raise ValueError('Conditions require predicate and specific target')
        if approved(c):
            references(c)
    for q in questions:
        cost = q.get('cost', 1)
        if not isinstance(cost, (int, float)) or isinstance(cost, bool) or not math.isfinite(cost) or cost <= 0:
            raise ValueError('Question cost must be finite and positive')
        if not q.get('text') or not q.get('target'):
            raise ValueError('Question text and target required')
        for m in q.get('mappings', []):
            if m['condition_id'] not in byid or m.get('coverage') not in ('FULL', 'PARTIAL', 'NONE'):
                raise ValueError('Invalid mapping')
            mapping = m.get('answers', {})
            if set(mapping) != {'yes', 'no', 'unknown'} or any(v not in VALUES for v in mapping.values()) or mapping['unknown'] != 'unknown':
                raise ValueError('Explicit Yes/No/Unknown mapping required')
            if m['coverage'] == 'FULL' and set(mapping[a] for a in ('yes', 'no')) != {'true', 'false'}:
                raise ValueError('FULL mapping must resolve both polarities')
            if approved(m):
                if not approved(q) or not approved(byid[m['condition_id']]) or q['target'] != byid[m['condition_id']]['target']:
                    raise ValueError('Approved mapping requires approved, same-target question and condition')
                references(m)
    formula = review.get('formula')
    if formula:
        ids = leaves(formula['expression'])
        if not ids <= set(byid):
            raise ValueError('Formula refers to missing conditions')
        if approved(formula):
            if any(not approved(byid[i]) for i in ids):
                raise ValueError('Approved formula uses unapproved conditions')
            references(formula)
    return review


def select_questions(conditions, questions, required=None):
    """Weighted greedy set cover; unobservable/uncovered predicates stay explicit."""
    required = set(required if required is not None else
                   (c['id'] for c in conditions if c.get('necessity') in ('required_for_path', 'required_all_paths')))
    eligible = {c['id'] for c in conditions if approved(c) and c.get('operator_observable') is True}
    coverage = {q['id']: {m['condition_id'] for m in q.get('mappings', [])
                         if approved(q) and approved(m) and m['coverage'] == 'FULL'} & eligible
                for q in questions}
    remaining, selected = set(required), []
    while True:
        choices = [q for q in questions if coverage[q['id']] & remaining]
        if not choices:
            break
        q = min(choices, key=lambda q: (q.get('cost', 1)/len(coverage[q['id']] & remaining), q['id']))
        selected.append(q['id'])
        remaining -= coverage[q['id']]
    return {'selected_question_ids': selected, 'unresolved_condition_ids': sorted(remaining),
            'total_cost': sum(q.get('cost', 1) for q in questions if q['id'] in selected),
            'method': 'weighted_greedy_full_coverage_only'}


def evaluate_review(review, case):
    """Call after validate_review against the immutable source bundle."""
    plan = {'cve': review['cve'], 'questions': [dict(id=q['id'], flow='common') for q in review.get('questions', [])]}
    # Formula reasoning is independently checked here; do not accept parallel route claims.
    result = evidence_judge(plan, {**case, 'path_analysis': {},
                                  'source_record_status': review.get('source_record_status') or case.get('source_record_status')})
    binding = case.get('binding', {})
    at = instant(binding.get('evaluated_at'))
    def approved_at(item):
        return approved(item) and at is not None and instant(item['reviewed_at']) <= at
    records = case.get('evidence', [])
    ids = [e.get('id') for e in records]
    scope_ok = (at is not None and binding.get('cve') == review['cve'] and
                all(isinstance(binding.get(k), str) and binding[k].strip() and binding[k].casefold() not in ('unknown', '미확인') for k in BINDING)
                and all(isinstance(i, str) and i for i in ids) and len(ids) == len(set(ids)))
    byid = {e.get('id'): e for e in records}
    def usable(refs, kinds=()):
        if not scope_ok or not refs or not isinstance(refs, list):
            return False
        found = []
        for eid in refs:
            e = byid.get(eid)
            if not e or eid in case.get('excluded_evidence_ids', []):
                return False
            times = [instant(e.get(k)) for k in ('observed_at', 'reviewed_at', 'valid_until')]
            if (any(t is None for t in times) or not times[0] <= times[1] <= at <= times[2] or
                any(e.get('binding', {}).get(k) != binding[k] for k in BINDING) or
                any(not str(e.get(k, '')).strip() for k in ('source', 'quote', 'reviewer', 'kind'))):
                return False
            found.append(e)
        return set(kinds) <= {e['kind'] for e in found}
    facts = {c['id']: 'unknown' for c in review.get('conditions', [])}
    questions = {q['id']: q for q in review.get('questions', [])}
    candidates, supporting = {}, {}
    for answer in case.get('answers', []):
        q = questions.get(answer.get('question_id'))
        if not q or not approved_at(q) or not usable(answer.get('evidence_ids')):
            continue
        for m in q.get('mappings', []):
            condition=next(c for c in review['conditions'] if c['id']==m['condition_id'])
            if not approved_at(m) or not approved_at(condition) or m['coverage'] == 'NONE':
                continue
            value = m['answers'].get(answer.get('value'), 'unknown')
            if value != 'unknown':
                cid = m['condition_id']
                candidates.setdefault(cid, set()).add(value)
                supporting.setdefault(cid, []).extend(answer['evidence_ids'])
    conflicts = sorted(k for k, v in candidates.items() if len(v) > 1)
    for cid, values in candidates.items():
        if len(values) == 1:
            facts[cid] = next(iter(values))
    formula = review.get('formula') or {}
    valid_formula = approved_at(formula) and not review.get('identity_ambiguous') and review.get('source_record_status') != 'Rejected'
    truth = logic(formula['expression'], facts) if valid_formula else 'unknown'
    result['condition_values'] = facts
    result['formula_value'] = truth
    result['answer_conflicts'] = conflicts
    result['formula_complete'] = valid_formula and formula.get('coverage_complete') is True
    # Re-evaluate using only facts supported by structural analysis. Firewall answers
    # and generic operational observations alone cannot refute an exploit route.
    structural = {cid: value if usable(supporting.get(cid), {'reviewed_nonexecution_analysis'}) else 'unknown'
                  for cid, value in facts.items()}
    refuted = (valid_formula and formula.get('coverage_complete') is True and not conflicts and
               usable(case.get('formula_evidence_ids'), {'reviewed_complete_route_analysis'}) and
               logic(formula['expression'], structural) == 'false')
    if refuted:
        refs = sorted(set(case['formula_evidence_ids'] + [eid for cid, value in structural.items() if value != 'unknown' for eid in supporting[cid]]))
        result['proofs'].append({'id': 'reviewed-formula', 'status': 'not_affected', 'supported': True,
                                 'rule': 'complete_formula_structurally_refuted', 'evidence_ids': refs})
        if result['status'] in ('affected', 'fixed'):
            result.update(status='under_investigation', reason='Reviewed product and formula proofs conflict.', accepted_evidence_ids=[])
        elif result['status'] == 'under_investigation' and any(p.get('supported') for p in result['proofs'] if p['id'] != 'reviewed-formula'):
            pass  # Preserve conflicts already detected by the product evidence judge.
        else:
            result.update(status='not_affected', justification=None,
                          reason='Reviewed exhaustive formula and scoped structural evidence refute all modeled paths.',
                          impact_statement='Reviewed exhaustive CVE formula is structurally false for this asset scope.',
                          accepted_evidence_ids=sorted(set(result['accepted_evidence_ids'] + refs)))
    result['decision_trace'].append({'check': 'three_valued_formula', 'value': truth, 'complete': result['formula_complete'],
                                     'structural_refutation': bool(refuted), 'final_status': result['status']})
    if review.get('identity_ambiguous'):
        result.update(status='under_investigation',accepted_evidence_ids=[],reason='Resolve CVE identity before asset adjudication.')
        result['decision_trace'].append(dict(check='identity',outcome='unresolved',final_status=result['status']))
    result['remaining_answers_block_decision']=result['status']=='under_investigation'
    if not result['remaining_answers_block_decision']:
        result['next_steps']=[]
        result['missing_evidence']=[]
    graph=result['evidence_graph']
    for node in graph['nodes']:
        if node['id']=='decision':node['label']=result['status']
    if refuted:
        graph['nodes'].append(dict(id='reviewed-formula',kind='proof',label='Complete formula structural refutation',supported=True))
        graph['edges'].extend(dict(**{'from':'evidence:'+eid,'to':'reviewed-formula','relation':'supports'}) for eid in refs)
        graph['edges'].append({'from':'reviewed-formula','to':'decision','relation':'decision_basis' if result['status']=='not_affected' else 'conflicting_candidate'})
    return result
