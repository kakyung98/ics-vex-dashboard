"""Score exact real-asset scopes; unknown labels never become negative gold.

Independent review is declared provenance, not authenticated by this module.
"""
from collections import Counter
import re
from .operational_evidence_judge import BINDING,instant

STATUSES={'affected','not_affected','fixed','under_investigation'}


def scope_key(binding):
    if any(not isinstance(binding.get(k),str) or not binding[k].strip() or binding[k].casefold() in {'unknown','미확인'} for k in BINDING):
        raise ValueError('Gold and prediction need the complete CVE/asset/product/build/config/mode scope')
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',binding['cve']):raise ValueError('Real evaluation requires a CVE identifier')
    stamp=instant(binding.get('evaluated_at'))
    if stamp is None:raise ValueError('Gold and prediction need timezone-aware evaluated_at')
    return tuple(binding[k] for k in BINDING)+(stamp.isoformat(),)


def validate_gold(row):
    scope_key(row['binding'])
    if row.get('record_type')!='real_asset_impact_gold' or row.get('synthetic') is not False or row.get('asset_case_verified') is not True:
        raise ValueError('A declared verified real asset case is required; blank CVE work items and synthetic cases are not gold')
    if row.get('prediction_blind_review') is not True:raise ValueError('Gold must be independently reviewed without seeing predictions')
    raters=[row['rater_a'],row['rater_b']]
    names=[r.get('name','').strip() for r in raters]
    if not all(names) or names[0]==names[1]:raise ValueError('Two distinct declared independent raters are required')
    for r in raters:
        if 'actual_affected' not in r:raise ValueError('Unknown actual impact must be explicitly recorded as null')
        if r.get('actual_affected') is not None and type(r['actual_affected']) is not bool:
            raise ValueError('Actual impact labels must be true, false or null')
        if not r.get('source') or not r.get('quote'):raise ValueError('Each rater needs an evidence source and quoted record')
    if 'actual_affected' not in row:raise ValueError('Unknown actual impact must be explicitly recorded as null')
    actual=row['actual_affected']
    if actual is not None and type(actual) is not bool:raise ValueError('Actual impact labels must be true, false or null')
    if raters[0].get('actual_affected')==raters[1].get('actual_affected'):
        if actual!=raters[0].get('actual_affected'):raise ValueError('Consensus label does not match the rater agreement')
    else:
        adjudicator=row.get('adjudication') or {}
        if (not adjudicator.get('name') or adjudicator['name'] in names or not adjudicator.get('source')
                or not adjudicator.get('quote') or 'actual_affected' not in adjudicator
                or adjudicator['actual_affected']!=actual):
            raise ValueError('Disagreement requires a separate declared adjudicator and evidence')


def score(predictions,gold,target_percent=85):
    byprediction={};bygold={}
    for row in predictions:
        key=scope_key(row['binding'])
        if key in byprediction:raise ValueError('Duplicate prediction scope')
        if row['status'] not in STATUSES:raise ValueError('Unknown predicted VEX status')
        byprediction[key]=row
    for row in gold:
        validate_gold(row);key=scope_key(row['binding'])
        if key in bygold:raise ValueError('Duplicate gold scope')
        bygold[key]=row
    if not byprediction or byprediction.keys()!=bygold.keys():
        raise ValueError('Predictions and frozen gold must have the exact same nonempty asset-scope population')
    tp=fp=tn=fn=unjudged_positive=known=positive_gold=positive_abstentions=abstentions=0
    negative_abstentions=unjudged_negative=false_clearances=0
    status_counts=Counter()
    for key,pred in byprediction.items():
        status=pred['status'];actual=bygold[key]['actual_affected'];status_counts[status]+=1
        abstentions+=status=='under_investigation'
        if actual is None:
            unjudged_positive+=status=='affected'
            unjudged_negative+=status in {'fixed','not_affected'}
            continue
        known+=1;positive_gold+=actual
        if actual:
            tp+=status=='affected';fn+=status!='affected'
            positive_abstentions+=status=='under_investigation'
            false_clearances+=status in {'fixed','not_affected'}
        elif status=='affected':fp+=1
        elif status in {'not_affected','fixed'}:tn+=1
        else:negative_abstentions+=1
    precision=100*tp/(tp+fp) if tp+fp else None
    recall=100*tp/positive_gold if positive_gold else None
    complete_precision=precision if not unjudged_positive else None
    n=tp+fp;interval=None
    if n:
        from math import sqrt
        z=1.95996398454;p=tp/n;den=1+z*z/n
        mid=(p+z*z/(2*n))/den;half=z*sqrt(p*(1-p)/n+z*z/(4*n*n))/den
        interval=[100*(mid-half),100*(mid+half)]
    count=len(byprediction)
    return dict(cases=count,declared_real_asset_gold_cases=count,known_impact_labels=known,
        unknown_impact_labels=count-known,gold_coverage=known/count,status_counts=dict(status_counts),
        TP=tp,FP=fp,TN=tn,FN_including_positive_abstentions=fn,positive_gold_cases=positive_gold,
        positive_abstentions=positive_abstentions,unjudged_predicted_affected=unjudged_positive,
        negative_abstentions=negative_abstentions,false_clearances=false_clearances,
        unjudged_fixed_or_not_affected=unjudged_negative,
        precision_on_judged_predictions_percent=precision,precision_percent=complete_precision,
        recall_including_abstentions_percent=recall,
        f1_including_abstentions_percent=200*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
        abstention_fraction=abstentions/count,decision_coverage=1-abstentions/count,
        nominal_precision_on_judged_wilson_95_percent=interval,target_percent=target_percent,
        target_met=complete_precision>=target_percent if complete_precision is not None else None,
        target_met_by_nominal_lower_bound=interval[0]>=target_percent if interval and complete_precision is not None else None,
        provenance_verification='Declared independent review metadata validated; identity, source truth and independence require external audit',
        interval_limit='Nominal binomial interval; correlated advisory/product groups require group-aware uncertainty analysis')
