"""Validation-only threshold selection; pending/model labels cannot authorize it."""
import math

def wilson_lower(correct,total):
    if not total:return 0.0
    z=1.959963984540054;p=correct/total
    return (p+z*z/(2*total)-z*math.sqrt(p*(1-p)/total+z*z/(4*total*total)))/(1+z*z/total)

def calibrate(rows,*,minimum_precision=.99,minimum_accepted=50):
    if not rows:return {'status':'insufficient_independent_labels','runtime_fuzzy_acceptance':False}
    for r in rows:
        if r.get('split')!='validation' or r.get('review_status')!='adjudicated' or r.get('annotation_basis')!='human_reviewed_identity' or len(set(r.get('reviewers',[])))<2:
            raise ValueError('Use independently reviewed validation identities, not test/model/weak labels.')
        if not isinstance(r.get('top1_correct'),bool) or not all(isinstance(r.get(k),(int,float)) and math.isfinite(r[k]) for k in ['score','margin']):
            raise ValueError('Invalid calibration record.')
    # Deterministic grid derived from validation values, no held-out test access.
    scores=sorted({r['score'] for r in rows});margins=sorted({r['margin'] for r in rows})
    # Bound runtime for large annotation sets using validation quantiles only.
    def grid(values):return sorted({values[round(i*(len(values)-1)/min(39,len(values)-1))] for i in range(min(40,len(values)))}) if len(values)>1 else values
    best=None
    for score in grid(scores):
        for margin in grid(margins):
            kept=[r for r in rows if r['score']>=score and r['margin']>=margin]
            n=len(kept);correct=sum(r['top1_correct'] for r in kept);lower=wilson_lower(correct,n)
            if n>=minimum_accepted and lower>=minimum_precision:
                candidate={'minimum_score':score,'minimum_margin':margin,'accepted':n,'correct':correct,
                    'validation_precision':correct/n,'wilson95_lower':lower,'coverage':n/len(rows)}
                if best is None or n>best['accepted']:best=candidate
    return {'status':'validation_threshold_proposed' if best else 'no_threshold_meets_requirement','threshold':best,
            'validation_examples':len(rows),'minimum_precision':minimum_precision,'minimum_accepted':minimum_accepted,
            'runtime_fuzzy_acceptance':False,'independent_heldout_confirmation_required':True,
            'test_used_for_threshold_selection':False,'scores_are_probabilities':False}
