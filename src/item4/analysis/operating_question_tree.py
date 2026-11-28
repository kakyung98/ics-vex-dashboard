"""Adaptive presentation of immutable V2 logic; never a VEX decision."""
from copy import deepcopy
from src.item4.decision.condition_logic_evaluation import logic, leaves

VERSION = 'item4-operating-question-tree/1'


def build(job, cases, questions):
    results = {r['cve']: r for r in job.get('conditions', [])}
    plans = []
    for case in cases:
        draft = (results.get(case['cve'], {}).get('prerequisite') or {}).get('draft', {})
        scenarios = deepcopy(draft.get('scenarios', []))
        expressions = [s['expression'] for s in scenarios]
        expression = (expressions[0] if len(expressions) == 1 else
                      dict(op='or', args=expressions) if expressions else None)
        referenced = leaves(expression) if expression else set()
        available = {q['condition_id']: q for q in questions if q['case_id'] == case['id']}
        order = list(dict.fromkeys([a['id'] for a in draft.get('prerequisites', [])] + sorted(referenced)))
        plans.append(dict(version=VERSION, case_id=case['id'], cve=case['cve'],
            component_ref=case['declared_ref'], expression=expression, scenarios=scenarios,
            condition_order=order,
            questions={cid: dict(id=q['id'], label=q['label'], positive_fact=q.get('positive_fact', q['label']))
                       for cid, q in available.items()},
            standalone_condition_ids=[cid for cid in order if cid in available and cid not in referenced],
            unavailable_condition_ids=sorted(referenced - set(available)),
            source_unknowns=deepcopy(draft.get('unknowns', [])),
            policy='Three-valued source logic only. Skipped questions remain unanswered; '
                   'source gaps and V4 product, scope and evidence gates remain authoritative.'))
    return plans


def needed(expression, facts):
    if not expression or logic(expression, facts) != 'unknown': return set()
    if 'condition' in expression: return {expression['condition']}
    return set().union(*(needed(a, facts) for a in expression['args']))


def snapshot(plan, answers, asked_question_ids=()):
    """Unknown counts as visited only when explicitly acknowledged by the user."""
    questions = plan['questions']
    facts = {cid: {'o':'true', 'x':'false'}.get(answers.get(q['id']), 'unknown')
             for cid, q in questions.items()}
    pending = needed(plan['expression'], facts)
    asked = set(asked_question_ids)
    next_cid = next((cid for cid in plan['condition_order'] if cid in pending and cid in questions
                     and questions[cid]['id'] not in asked and facts[cid] == 'unknown'), None)
    if next_cid is None:
        next_cid = next((cid for cid in plan['standalone_condition_ids']
                         if questions[cid]['id'] not in asked and facts[cid] == 'unknown'), None)
    return dict(value=logic(plan['expression'], facts) if plan['expression'] else 'unknown',
        next_question_id=questions[next_cid]['id'] if next_cid else None,
        needed_condition_ids=[cid for cid in plan['condition_order'] if cid in pending],
        skipped_condition_ids=[cid for cid in plan['condition_order']
            if cid not in pending and cid not in plan['standalone_condition_ids'] and cid in questions
            and facts[cid] == 'unknown'],
        relationship_unresolved=bool(plan['standalone_condition_ids']) or plan['expression'] is None,
        source_unknowns=plan['source_unknowns'], final_vex_decision=False)
