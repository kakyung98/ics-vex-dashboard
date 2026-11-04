"""Independent-label evaluation, never LLM-as-judge ground truth."""
from collections import Counter
import math
from src.vex_roles import fingerprint

LABELS=('likely_affected','likely_not_affected','likely_mitigated','likely_cannot_determine')


def wilson_upper(errors,total):
    if not total:return None
    z=1.959963984540054;p=errors/total
    return (p+z*z/(2*total)+z*math.sqrt(p*(1-p)/total+z*z/(4*total*total)))/(1+z*z/total)


def require_gold(row):
    if row.get('review_status')!='adjudicated' or len(set(row.get('reviewers',[])))<2 or not row.get('adjudicator'):
        raise ValueError('Independent two-reviewer adjudication is required: '+str(row.get('id')))
    if row.get('annotation_basis')!='human_reviewed_source_and_scenario':
        raise ValueError('Model-generated or weak labels cannot be treated as independent test gold.')


def evaluate_assessments(gold,predictions):
    refs={r['id']:r for r in gold};pred={r['id']:r for r in predictions}
    if len(refs)!=len(gold) or len(pred)!=len(predictions) or set(pred)-set(refs):raise ValueError('Duplicate or foreign prediction IDs.')
    confusion=Counter();schema=0;unsafe=0;missed_affected=0;affected=0;decided=0
    for rid,row in refs.items():
        require_gold(row);g=row['assessment']
        if g not in LABELS:raise ValueError('Unknown gold label.')
        p=pred.get(rid,{}).get('assessment');valid=isinstance(p,str) and p in LABELS
        schema+=valid
        if not valid:p='invalid_or_missing'
        confusion[g,p]+=1
        unsafe+=p=='likely_not_affected' and g!='likely_not_affected'
        affected+=g=='likely_affected'
        missed_affected+=g=='likely_affected' and p=='likely_not_affected'
        decided+=valid and p!='likely_cannot_determine'
    per_class={}
    for label in LABELS:
        tp=confusion[label,label];fn=sum(n for (g,p),n in confusion.items() if g==label and p!=label)
        fp=sum(n for (g,p),n in confusion.items() if p==label and g!=label)
        per_class[label]={'support':tp+fn,'precision':tp/(tp+fp) if tp+fp else None,
            'recall':tp/(tp+fn) if tp+fn else None,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}
    n=len(refs)
    return {'examples':n,'schema_rate':schema/n if n else None,
        'macro_f1':sum(v['f1'] or 0 for v in per_class.values())/len(LABELS) if n else None,
        'per_class':per_class,'confusion':[{'gold':g,'prediction':p,'count':c} for (g,p),c in sorted(confusion.items())],
        'unsafe_clearances':unsafe,'unsafe_clearance_rate_all_cases':unsafe/n if n else None,
        'affected_to_not_affected':missed_affected,'gold_affected_cases':affected,
        'affected_to_not_affected_rate':missed_affected/affected if affected else None,
        'affected_to_not_affected_wilson95_upper':wilson_upper(missed_affected,affected),
        'decision_coverage':decided/n if n else None,'abstention_or_invalid_rate':1-decided/n if n else None,
        'test_labels_independently_reviewed':True}


def evaluate_questions(gold,predictions,reviews):
    refs={r['id']:r for r in gold};pred={r['id']:r for r in predictions};judged={r['id']:r for r in reviews}
    if len(refs)!=len(gold) or len(pred)!=len(predictions) or len(judged)!=len(reviews) or set(pred)-set(refs) or set(judged)-set(refs):raise ValueError('Duplicate or foreign IDs.')
    questions=grounded=answerable=supported=covered=necessary=nonleading=0;missing_reviews=0;missing_predictions=0
    for rid,row in refs.items():
        require_gold(row)
        targets={c['id'] for c in row['required_conditions']};necessary+=len(targets);seen=set()
        qs=pred.get(rid,{}).get('questions',[]);review=judged.get(rid)
        if not isinstance(qs,list) or not all(isinstance(q,dict) for q in qs):raise ValueError('Questions must be a list of objects.')
        missing_predictions+=not bool(qs)
        if review:
            require_gold(review)
            if review.get('prediction_sha256')!=fingerprint(pred.get(rid,{})):
                raise ValueError('Human question review does not match the prediction hash.')
            if len(review.get('question_reviews',[]))!=len(qs):raise ValueError('One review per generated question is required.')
        elif qs:missing_reviews+=len(qs)
        for i,q in enumerate(qs):
            questions+=1;quote=q.get('evidence')
            grounded+=isinstance(quote,str) and bool(quote.strip()) and quote in row['description']
            if review:
                r=review['question_reviews'][i]
                if not set(r['condition_ids'])<=targets:raise ValueError('Foreign condition ID in question review.')
                answerable+=r.get('operator_answerable') is True
                supported+=r.get('no_unsupported_assumptions') is True
                nonleading+=r.get('non_leading') is True
                if all(r.get(k) is True for k in ['operator_answerable','no_unsupported_assumptions','non_leading']):seen.update(r['condition_ids'])
        covered+=len(seen)
    return {'examples':len(refs),'generated_questions':questions,'literal_quote_rate':grounded/questions if questions else None,
        'operator_answerable_rate':answerable/questions if questions else None,
        'supported_question_rate':supported/questions if questions else None,'non_leading_rate':nonleading/questions if questions else None,
        'condition_coverage_recall':covered/necessary if necessary else None,'required_conditions':necessary,
        'unreviewed_questions':missing_reviews,'missing_or_empty_predictions':missing_predictions,
        'semantic_evaluation_complete':bool(refs) and not missing_reviews and not missing_predictions,
        'note':'Question meaning/condition mappings require independent human review; literal quotes alone are not quality.'}
