"""Advisory uncertainty gates; operator reports never become code-absence proof."""
from collections import defaultdict


def assessment_gate(prediction, questions, *, valid, generation_valid, version_decided):
    errors=[]
    if not valid or not generation_valid:
        errors.append('assessment_or_question_contract_not_accepted')
    if not version_decided:errors.append('installed_product_version_applicability_unresolved')
    operating=[q for q in questions if q.get('origin')=='llm' and not q.get('deprecated_version_field')]
    records={q['id'] for q in operating if q['answer'].get('value') not in {None,'','unknown'}
             and q['answer'].get('evidence','').strip()}
    if not records:errors.append('no_operating_answer_with_supporting_record')
    refs=prediction.get('answer_refs',[]) if isinstance(prediction,dict) else []
    if not isinstance(refs,list) or not records.intersection(str(r) for r in refs):
        errors.append('model_did_not_reference_recorded_operating_facts')
    seen=defaultdict(set)
    for q in operating:
        value=q['answer'].get('value')
        if value not in {None,'','unknown'}:seen[' '.join(q['question'].casefold().split())].add(value)
    if any(len(values)>1 for values in seen.values()):errors.append('conflicting_answers_to_identical_question')
    raw=prediction.get('assessment') if isinstance(prediction,dict) else None
    return {'assessment':'likely_cannot_determine' if errors else raw,'errors':errors,
            'raw_assessment':raw,'standard_vex_authority':False,
            'reported_facts_independently_verified':False}
