"""Explicit condition/question/answer coverage; never a claim of source completeness."""
from src.item4.decision.condition_logic_evaluation import leaves


def coverage(job, cases, questions, extraction_rejections=(), question_rejections=()):
    results={r['cve']:r for r in job.get('conditions',[])}
    rows=[]
    for case in cases:
        draft=(results.get(case['cve'],{}).get('prerequisite') or {}).get('draft',{})
        placed=set().union(*(leaves(s['expression']) for s in draft.get('scenarios',[])))
        required=set(placed)
        required.update(p['id'] for p in draft.get('prerequisites',[])
            if p.get('necessity','required') in ('required','alternative'))
        mapped={q['condition_id']:q for q in questions if q['case_id']==case['id']}
        rejected={r['condition_id']:'extraction_confidence_rejected' for r in extraction_rejections if r['case_id']==case['id']}
        rejected.update({r['condition_id']:'question_confidence_rejected' for r in question_rejections if r['case_id']==case['id']})
        conditions=[]
        for cid in sorted(required):
            q=mapped.get(cid);answer=job.get('answers',{}).get(q['id'],'unknown') if q else 'unknown'
            state={'o':'true','x':'false','holds':'true','absent':'false'}.get(answer,'unknown')
            conditions.append(dict(condition_id=cid,question_ids=[q['id']] if q else [],
                question_covered=bool(q),answer_covered=state!='unknown',value=state,
                gap_reason=None if q else rejected.get(cid,'condition_not_bound_to_source_scenario' if cid not in placed
                    else 'question_unavailable_or_condition_unobservable')))
        total=len(required);asked=sum(c['question_covered'] for c in conditions);answered=sum(c['answer_covered'] for c in conditions)
        rows.append(dict(case_id=case['id'],cve=case['cve'],component_ref=case['declared_ref'],
            total_conditions=total,question_covered=asked,answer_covered=answered,
            question_coverage=asked/total if total else None,answer_coverage=answered/total if total else None,
            conditions=conditions,source_path_completeness_established=False))
    return rows
