"""Compile cluster-local question reuse and execute scoped CVE formulas.

Clusters propose reuse candidates. Only source-validated review contracts enter
the executable plan; neither shared text nor model necessity labels approve one.
"""
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import re

from .context_vex_pipeline import approved, leaves, logic, select_questions, validate_review, evaluate_review
from .operational_evidence_judge import BINDING

SCOPE = tuple(k for k in BINDING if k != 'cve') + ('evaluated_at',)
VALUES = {'yes', 'no', 'unknown'}
TEMPLATES = {
    'network_reachable': 'Can the assessed origin reach {target} through the specified network path?',
    'attacker_authenticated': 'Does the assessed actor have an authenticated session for {target}?',
    'attacker_has_required_privilege': 'Does the assessed actor hold the required privilege for {target}?',
    'feature_enabled': 'Is {target} enabled in the assessed operating mode?',
    'input_processed': 'Is {target} processed in this operating workflow?',
    'user_performs_action': 'Does the operator perform the action specified for {target}?',
    'adversary_can_write': 'Can the assessed actor write to {target}?',
}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def draft_question(condition):
    """Deterministic wording from a structured atom; review is never inherited."""
    predicate, target = condition.get('predicate'), condition.get('target')
    if predicate not in TEMPLATES or not isinstance(target, str) or not target.strip() or target.casefold() in {'unresolved','unknown','미확인'}:
        raise ValueError('A supported predicate and a specific target are required')
    return dict(id=condition['id']+':question', text=TEMPLATES[predicate].format(target=target),
                target=target, cost=1, answer_type='yes_no_unknown',
                validation_status='pending_review',
                derivation=dict(condition_id=condition['id'], template=predicate),
                mappings=[dict(condition_id=condition['id'], coverage='FULL',
                               answers=dict(yes='true', no='false', unknown='unknown'),
                               source_refs=deepcopy(condition.get('source_refs', [])),
                               validation_status='pending_review')])


def screen_candidate(row):
    """Triage flags only: retain the record, never assert a replacement fact."""
    text = row['condition']
    flags = []
    if re.search(r'(?i)\b(?:execute|execution of|executed|gain|obtain|compromise|crash|disclos)\w*\b', text):
        flags.append('possible_consequence_mixed_with_precondition')
    if re.search(r'(?i)\b(?:versions?|prior to|before|vulnerable|buffer overflow|out.of.bounds)\b', text):
        flags.append('possible_applicability_or_weakness_instead_of_operating_fact')
    if row.get('necessity') in {'not_required', 'explicitly_not_a_necessary_condition'}:
        flags.append('must_not_be_used_as_required_positive_literal')
    return dict(condition_id=row['condition_id'], cve=row['cve'], flags=flags,
                disposition='needs_source_review', retained=True,
                original_necessity=row['necessity'], semantic_verified=False)


def _unique(rows, name):
    result = {r['cve']: r for r in rows}
    if len(result) != len(rows):
        raise ValueError('Duplicate CVE in '+name)
    return result


def needed_conditions(expression, facts):
    """Unknown leaves still capable of changing the reviewed formula's truth."""
    if logic(expression, facts) != 'unknown':
        return set()
    if 'condition' in expression:
        return {expression['condition']}
    return set().union(*(needed_conditions(child, facts) for child in expression['args']))


def _signature(question, conditions):
    # Exact wording is an additional conservative guard, never the sole proof.
    mappings = sorted([(conditions[m['condition_id']]['predicate'],
                        conditions[m['condition_id']]['target'], m['answers'])
                       for m in question.get('mappings', [])
                       if approved(m) and m['coverage'] == 'FULL'], key=digest)
    return digest(dict(text=' '.join(question['text'].split()), target=question['target'],
                       mappings=mappings, evidence_requirements=question.get('evidence_requirements', [])))


def compile_plan(reviews, records, memberships):
    """Separate shared cluster-local questions from CVE-specific residuals."""
    reviews = deepcopy(reviews)
    byrecord = _unique(records, 'sources')
    byreview = _unique(reviews, 'reviews')
    bymember = _unique(memberships, 'memberships')
    if set(byrecord) != set(byreview) or set(bymember) != set(byreview):
        raise ValueError('Sources, reviews and memberships must have the same CVE population')
    occurrences, selections = [], {}
    for cve, review in sorted(byreview.items()):
        validate_review(review, byrecord[cve])
        # Source identity is authoritative, never a client-supplied override.
        review['identity_ambiguous'] = byrecord[cve].get('identity_ambiguous', False)
        review['source_record_status'] = byrecord[cve].get('original_nvd_status')
        required = leaves(review['formula']['expression']) if review.get('formula') else None
        selection = select_questions(review['conditions'], review['questions'], required)
        selections[cve] = selection
        conditions = {c['id']: c for c in review['conditions']}
        groups = bymember[cve].get('cluster_ids', [])
        if len(groups) != len(set(groups)):
            raise ValueError('Duplicate cluster membership')
        for question in review['questions']:
            if question['id'] not in selection['selected_question_ids']:
                continue
            mappings = question.get('mappings', [])
            # Sharing requires complete reviewed meaning for every claimed mapping.
            shareable = question['target'].casefold() not in {'unresolved','unknown','미확인'} and bool(mappings) and all(approved(m) and m['coverage'] == 'FULL' and
                approved(conditions[m['condition_id']]) for m in mappings)
            occurrences.append(dict(cve=cve, question_id=question['id'], question=question,
                                    signature=_signature(question, conditions) if shareable else None,
                                    cluster_ids=sorted(groups)))
    grouped = defaultdict(list)
    for occurrence in occurrences:
        if occurrence['signature']:
            grouped[occurrence['signature']].append(occurrence)
    common, common_refs = [], {}
    for signature, members in sorted(grouped.items()):
        support = defaultdict(set)
        for member in members:
            for cluster in member['cluster_ids']:
                support[cluster].add(member['cve'])
        shared_clusters = {k for k,v in support.items() if len(v) >= 2}
        participants = [m for m in members if shared_clusters.intersection(m['cluster_ids'])]
        if not shared_clusters:
            continue
        qid = 'common:'+signature[:24]
        first = participants[0]['question']
        entry = dict(id=qid, text=first['text'], target=first['target'],
                     cluster_ids=sorted(shared_clusters), answer_type='yes_no_unknown',
                     evidence_requirements=first.get('evidence_requirements', []),
                     members=[dict(cve=m['cve'], question_id=m['question_id']) for m in participants],
                     common_to_entire_cluster=False,
                     rule='Identical reviewed meaning and target; applies only to listed CVE members')
        common.append(entry)
        for member in participants:
            common_refs[(member['cve'],member['question_id'])] = qid
    plans = []
    for cve, review in sorted(byreview.items()):
        selected = set(selections[cve]['selected_question_ids'])
        common_ids = sorted({common_refs[(cve,q)] for q in selected if (cve,q) in common_refs})
        specific = [deepcopy(q) for q in review['questions']
                    if q['id'] in selected and (cve,q['id']) not in common_refs]
        plans.append(dict(cve=cve, cluster_ids=sorted(bymember[cve].get('cluster_ids', [])),
                          common_question_ids=common_ids, specific_questions=specific,
                          unresolved_condition_ids=selections[cve]['unresolved_condition_ids'],
                          formula=deepcopy(review.get('formula')),
                          pending_questions=[q for q in review['questions'] if not approved(q)]))
    plan = dict(schema='ics-vex-cluster-question-plan/1', common_questions=common,
                cves=plans, reviews=reviews,
                source_digest=digest(records), memberships_digest=digest(memberships),
                reuse_scope=list(SCOPE), question_selection='weighted greedy reviewed FULL mappings')
    plan['plan_id'] = digest(plan)
    return plan


def evaluate_plan(plan, records, cases, common_answers=()):
    """Propagate shared answers with CVE-specific evidence, then use the judge."""
    supplied = deepcopy(plan)
    plan_id = supplied.pop('plan_id', None)
    if digest(supplied) != plan_id or digest(records) != plan['source_digest']:
        raise ValueError('Plan or source snapshot changed; recompile before answering')
    byrecord = _unique(records, 'sources')
    reviews = _unique(plan['reviews'], 'reviews')
    case_bycve = {}
    for case in deepcopy(cases):
        cve = case['binding']['cve']
        if cve in case_bycve or cve not in reviews:
            raise ValueError('Duplicate or unknown CVE asset case')
        case_bycve[cve] = case
    common = {q['id']:q for q in plan['common_questions']}
    cveplans = {p['cve']:p for p in plan['cves']}
    rejections, propagation = [], []
    for answer in common_answers:
        q = common.get(answer.get('question_id'))
        if answer.get('plan_id') != plan_id or not q or answer.get('value') not in VALUES:
            raise ValueError('Shared answer needs current plan ID, known question and yes/no/unknown')
        if answer.get('target') != q['target']:
            raise ValueError('Shared answer target mismatch')
        for member in q['members']:
            cve = member['cve']
            case = case_bycve.get(cve)
            if case is None:
                continue
            scope = {k:case['binding'].get(k) for k in SCOPE}
            evidence_ids = answer.get('evidence_by_cve', {}).get(cve, [])
            if answer.get('scope') != scope or not evidence_ids:
                rejections.append(dict(cve=cve, question_id=q['id'],
                                       reason='Scope mismatch or missing CVE-specific evidence references'))
                continue
            case.setdefault('answers', []).append(dict(question_id=member['question_id'],
                  value=answer['value'], evidence_ids=evidence_ids,
                  origin_common_question_id=q['id'], plan_id=plan_id))
            propagation.append(dict(cve=cve, common_question_id=q['id'],
                                    question_id=member['question_id'], evidence_ids=evidence_ids))
    results = []
    for cve, case in sorted(case_bycve.items()):
        validate_review(reviews[cve], byrecord[cve])
        result = evaluate_review(reviews[cve], case)
        result['question_plan_id'] = plan_id
        questions_by_id={q['id']:q for q in reviews[cve]['questions']}
        result['question_answer_trace'] = [dict(question_id=a.get('question_id'), value=a.get('value'),
            evidence_ids=a.get('evidence_ids', []), common_question_id=a.get('origin_common_question_id'),
            question_text=questions_by_id.get(a.get('question_id'),{}).get('text'),
            target=questions_by_id.get(a.get('question_id'),{}).get('target'),
            condition_ids=[m['condition_id'] for m in questions_by_id.get(a.get('question_id'),{}).get('mappings',[])])
            for a in case.get('answers', [])]
        result['condition_definitions']=[{k:deepcopy(c.get(k)) for k in
            ('id','predicate','target','necessity','operator_observable','source_refs','validation_status')}
            for c in reviews[cve]['conditions']]
        result['formula_definition']=deepcopy(reviews[cve].get('formula'))
        formula=reviews[cve].get('formula')
        needed=(needed_conditions(formula['expression'],result['condition_values'])
                if formula and approved(formula) else
                {c['id'] for c in reviews[cve]['conditions'] if result['condition_values'][c['id']]=='unknown'})
        if result['status']!='under_investigation':
            needed=set()  # A valid scoped final proof ends the required questionnaire.
        def relevant(question):
            return any(m['condition_id'] in needed for m in question.get('mappings', []))
        result['remaining_logical_condition_ids']=sorted(needed)
        result['next_specific_questions']=[q for q in cveplans[cve]['specific_questions'] if relevant(q)]
        byquestion={q['id']:q for q in reviews[cve]['questions']}
        result['next_common_question_ids']=[q['id'] for q in plan['common_questions']
            if any(m['cve']==cve and relevant(byquestion[m['question_id']]) for m in q['members'])]
        results.append(result)
    return dict(plan_id=plan_id, decisions=results, propagated_answers=propagation,
                rejected_propagations=rejections,
                awaiting_asset_cves=sorted(set(reviews)-set(case_bycve)))


def export_openvex(evaluation, author, timestamp):
    """Serialize evidence-judge decisions, never provisional cluster likelihoods."""
    from .operational_evidence_judge import instant
    if not isinstance(author,str) or not author.strip() or instant(timestamp) is None:
        raise ValueError('Author and timezone-aware timestamp required')
    statements=[]
    for decision in evaluation['decisions']:
        binding=decision['binding']
        product_scope={k:binding[k] for k in SCOPE if k != 'evaluated_at'}
        vulnerability_id=('https://nvd.nist.gov/vuln/detail/'+decision['cve']
                          if re.fullmatch(r'CVE-\d{4}-\d{4,}', decision['cve'])
                          else 'urn:ics-vex:internal-vulnerability:'+digest(decision['cve']))
        statement=dict(vulnerability={'@id':vulnerability_id,
                                      'name':decision['cve']},
                       products=[{'@id':'urn:ics-vex:scoped-product:'+digest(product_scope)}],
                       timestamp=binding['evaluated_at'],
                       status=decision['status'], status_notes=decision['reason'])
        for field in ('justification','impact_statement','action_statement'):
            if decision.get(field):
                statement[field]=decision[field]
        statements.append(statement)
    return {'@context':'https://openvex.dev/ns/v0.2.0',
            '@id':'urn:ics-vex:cluster-question-evaluation:'+digest(evaluation),
            'author':author, 'timestamp':timestamp, 'version':1, 'statements':statements}
