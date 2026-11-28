"""Extraction-conditioned operator worlds with separate source and logic references."""
from copy import deepcopy
import hashlib
import itertools
import json
import re

VERSION='item4-extracted-ox/3'
VALUES=('o','x','unknown')


def digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True).encode()).hexdigest()


def truth(expression, values):
    if 'condition' in expression:return values.get(expression['condition'])
    children=[truth(a,values) for a in expression['args']]
    if expression['op']=='not':return None if children[0] is None else not children[0]
    if expression['op']=='and':return False if False in children else True if all(c is True for c in children) else None
    if expression['op']=='or':return True if True in children else False if all(c is False for c in children) else None
    raise ValueError('Unknown source connective')


def terms(expr, negate=False, budget=1024):
    if 'condition' in expr:return [{expr['condition']:not negate}]
    op=expr['op']
    if op=='not':return terms(expr['args'][0],not negate,budget)
    if negate:op={'and':'or','or':'and'}[op]
    children=[terms(a,negate,budget) for a in expr['args']]
    result=[t for child in children for t in child] if op=='or' else [{}]
    if op=='and':
        for child in children:
            result=[dict(a,**b) for a in result for b in child if all(k not in a or a[k]==v for k,v in b.items())]
            if len(result)>budget:raise ValueError('DNF budget exceeded')
    if len(result)>budget:raise ValueError('DNF budget exceeded')
    return result


def answer_vectors(questions, expressions=()):
    """Exhaustive through five atoms; deterministic boundary coverage above five."""
    questions=sorted(questions,key=lambda q:q['id']);ids=[q['id'] for q in questions]
    seen=set();rows=[]
    def add(v):
        key=tuple(v[k] for k in ids)
        if key not in seen:seen.add(key);rows.append(v)
    if len(ids)<=5:
        for values in itertools.product(VALUES,repeat=len(ids)):add(dict(zip(ids,values)))
    else:
        for base in VALUES:
            original=dict.fromkeys(ids,base);add(original)
            for key in ids:
                for value in VALUES:
                    if value!=base:add(dict(original,**{key:value}))
        by_condition={q['condition_id']:q['id'] for q in questions}
        for expression in expressions:
            try:witnesses=terms(expression)[:32]
            except ValueError:continue
            for term in witnesses:
                v=dict.fromkeys(ids,'unknown')
                for cid,value in term.items():
                    if cid in by_condition:v[by_condition[cid]]='o' if value else 'x'
                add(v)
                for cid in term:
                    if cid in by_condition:
                        qid=by_condition[cid];add(dict(v,**{qid:'unknown'}))
                        add(dict(v,**{qid:'x' if v[qid]=='o' else 'o'}))
    return rows,dict(mode='exhaustive_ternary' if len(ids)<=5 else 'three_bases_single_changes_plus_DNF_witnesses',
        atom_count=len(ids),vectors=len(rows),all_combinations=3**len(ids),exhaustive=len(ids)<=5)


def normalize(text):
    return re.sub(r'^(?:when|if)\s+','', ' '.join(str(text).casefold().split())).strip(' .,:;')


def source_bindings(questions, reference):
    """Conservative identical-clause correspondence; no semantic similarity guess.

    The reference expression is frozen before the evaluated model inference.
    No extracted expression or model verdict is used as the source oracle.
    """
    path=reference.get('selected_path') or {};matches={};audit=[]
    for atom in path.get('conditions',[]):
        ref=atom['source_ref'];candidates=[]
        for q in questions:
            if not any(r['source_id']==ref['source_id'] for r in q.get('source_refs',[])):continue
            if normalize(q.get('operational_quote'))!=normalize(ref['quote']):continue
            # Inversion and coordinated wording need independent annotation.
            if re.search(r'\b(?:not|unless|without|disabled|unreachable|unavailable|absent|blocked|and|or)\b',ref['quote'],re.I):continue
            candidates.append(q['id'])
        if len(candidates)==1:matches[atom['id']]=candidates[0]
        audit.append(dict(reference_condition=atom['id'],question_ids=candidates,
            bound=len(candidates)==1,method='same_source_and_identical_positive_operational_clause'))
    # One answer cannot stand in for multiple independently specified atoms.
    repeated={qid for qid in matches.values() if list(matches.values()).count(qid)>1}
    matches={cid:qid for cid,qid in matches.items() if qid not in repeated}
    return matches,audit


def candidate(case, reference, bindings, *, component_ref=None):
    context=case['context']
    if context.get('deployment')=='not_deployed':
        from src.item4.decision.inventory_evidence_policy import absence_hold_reason
        hold = absence_hold_reason(context, component_ref or case.get('component_ref'))
        if hold:
            return None, hold
        return False,'conditional_complete_inventory_absence'
    if context.get('deployment')!='running' or context.get('runtime')!='bom':return None,'unresolved_deployment_or_running_version'
    if context.get('scope')!='current_single' or context.get('mode') in ('unknown','mixed') or context.get('origin')=='unknown':
        return None,'unresolved_assessment_scope'
    path=reference.get('selected_path')
    if not path:return None,'no_independent_source_path'
    values={cid:{'o':True,'x':False}.get(case['answers'].get(qid)) for cid,qid in bindings.items()}
    return truth(path['expression'],values),'frozen_source_expression_with_partial_exact_clause_binding'


def logic_reference(case, questions, expressions):
    values={q['condition_id']:{'o':True,'x':False}.get(case['answers'].get(q['id'])) for q in questions}
    if not expressions:return None
    return truth(dict(op='or',args=list(expressions)),values)


def build_cases(cve, job, reference):
    questions=job['questions'];draft=((job['conditions'][0].get('prerequisite') or {}).get('draft') or {})
    expressions=[s['expression'] for s in draft.get('scenarios',[])]
    vectors,coverage=answer_vectors(questions,expressions)
    component=job['assessment_cases'][0].get('component') if job['assessment_cases'] else None
    from src.item4.decision.asset_vex_assessment import concrete
    base=dict(scope='current_single',mode='normal',origin='same_zone',deployment='running',
        runtime='bom' if component and concrete(component.get('version')) else 'unknown')
    cases=[];references=[];seen=set();bindings,audit=source_bindings(questions,reference)
    def add(answers,context,kind):
        identity=digest(dict(version=VERSION,cve=cve,answers=answers,context=context,plan=job['plan_sha256']))
        if identity in seen:return
        seen.add(identity)
        row=dict(id='OX3-'+identity[:28],cve=cve,answers=answers,context=context,synthetic=True)
        actual,method=candidate(row,reference,bindings,component_ref=component and component['ref'])
        cases.append(row)
        references.append(dict(id=row['id'],cve=cve,actual_affected=actual,label_method=method,
            independent_of_evaluated_LLM_expression=True,expert_validated=False,
            source_record_digest=reference.get('source_record_digest'),selected_path=reference.get('selected_path'),
            assumptions=['Frozen selected source path is complete only in this hypothetical world.',
                         'Same source product/build and explicitly supplied synthetic observations apply.'],
            input_kind=kind,logic_consistency_only=logic_reference(row,questions,expressions)))
    for vector in vectors:add(vector,deepcopy(base),'operating_condition_combination')
    unknown=dict.fromkeys((q['id'] for q in questions),'unknown')
    for key,value in [('scope','unknown'),('mode','unknown'),('origin','unknown'),('deployment','unknown'),
                      ('deployment','not_deployed'),('runtime','unknown'),('runtime','mixed')]:
        add(dict(unknown),dict(base,**{key:value}),'context_control')
    return cases,references,dict(coverage=coverage,source_condition_bindings=bindings,binding_audit=audit,
        independent_source_path_available=bool(reference.get('selected_path')),
        no_question_placeholder=not questions)


def metrics(predictions, references):
    gold={r['id']:r for r in references}
    assert len(predictions)==len({r['id'] for r in predictions})==len(gold)
    assert {r['id'] for r in predictions}==set(gold)
    tp=fp=fn=unknown=abstentions=0
    for p in predictions:
        actual=gold[p['id']]['actual_affected'];positive=p['status']=='affected'
        tp+=positive and actual is True;fp+=positive and actual is False
        fn+=not positive and actual is True;unknown+=positive and actual is None
        abstentions+=p['status']=='under_investigation'
    primary=tp/(tp+fp) if tp+fp and not unknown else None
    return dict(cases=len(predictions),TP=tp,FP=fp,FN=fn,unjudged_predicted_affected=unknown,
        precision=primary,precision_percent=100*primary if primary is not None else None,
        target_met=primary>.85 if primary is not None else None,formula='TP/(TP+FP)',strict_threshold=.85,
        known_candidate_only_diagnostic_precision=tp/(tp+fp) if tp+fp else None,
        abstention_rate=abstentions/len(predictions) if predictions else None)
