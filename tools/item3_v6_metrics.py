"""Pure full-output scoring for every paired v6 BOM, including conflict diagnostics."""
from collections import Counter

FIELDS=('TP','FP','FN','unjudged','out_of_scope')

def metrics(counts):
    tp,fp,fn=(counts.get(k,0) for k in ('TP','FP','FN'))
    judged=tp+fp;emitted=judged+counts.get('unjudged',0)+counts.get('out_of_scope',0)
    return {**{k:counts.get(k,0) for k in FIELDS},
        'precision_percent':100*tp/judged if judged and judged==emitted else None,
        'precision_on_adjudicated_percent':100*tp/judged if judged else None,
        'precision_lower_bound_percent':100*tp/emitted if emitted else None,
        'recall_on_known_positives_percent':100*tp/(tp+fn) if tp+fn else None,
        'output_adjudication_coverage_percent':100*judged/emitted if emitted else None}

def score_outputs(output,expected,unknown,universe):
    output=set(output);expected=set(expected);unknown=set(unknown)
    result=Counter()
    for cve in output:
        result['out_of_scope' if cve not in universe else 'unjudged' if cve in unknown else 'TP' if cve in expected else 'FP']+=1
    result['FN']=len(expected-output)
    return {k:result[k] for k in FIELDS}

def reported_conflict(row):
    validation=row.get('validation',{});l3=row.get('l3',{})
    return bool(l3.get('conflicts') or validation.get('identity_status')=='conflicting_evidence'
        or any('conflict' in str(reason).lower() for reason in validation.get('reasons',[])))

def case_score(result,gold,universe):
    rows=result.get('components',[])
    confirmed={f['cve_id'] for r in rows for f in r.get('cves',[]) if f.get('match_status')=='match'}
    candidates={f['cve_id'] for r in rows for f in r.get('cves',[]) if f.get('match_status')=='unknown'}
    stages=Counter(stage+':'+str((r.get(stage,{}).get('agent') or {}).get('status','not_recorded'))
        for r in rows for stage in ('l2','l3','l4'))
    return {'mapping':score_outputs(confirmed,gold['expected_cves'],gold['unknown_cves'],universe),
        'candidates':score_outputs(candidates,gold['expected_cves'],gold['unknown_cves'],universe),
        'reported_conflict':any(reported_conflict(r) for r in rows),
        'agent_stage_statuses':dict(stages),
        'confirmed_count':len(confirmed),'candidate_count':len(candidates),
        'error':result.get('error') or ('unexpected_component_count' if len(rows)!=1 else None)
            or next((r.get('l4',{}).get('lookup_error') for r in rows if r.get('l4',{}).get('lookup_error')),None)}

def aggregate(rows,total):
    all_counts=Counter();recoverable=Counter();groups={};folds={};safety=Counter();stages=Counter();errors=0;done=0
    for scenario,fold,score in rows:
        done+=1;errors+=bool(score['error']);all_counts.update(score['mapping'])
        stages.update(score.get('agent_stage_statuses',{}))
        groups.setdefault(scenario,Counter()).update(score['mapping'])
        folds.setdefault(fold,Counter()).update(score['mapping'])
        if not scenario.endswith('_wrong'):recoverable.update(score['mapping'])
        if scenario.endswith('_wrong'):
            safety['inputs']+=1;safety['reported_conflicts']+=score['reported_conflict']
            safety['deferred_without_confirmed_mapping']+=not score['confirmed_count']
            safety['inputs_with_wrong_confirmed_CVE_against_latent_gold']+=score['mapping']['FP']>0
            safety['wrong_confirmed_CVE_edges_against_latent_gold']+=score['mapping']['FP']
        elif score['reported_conflict']:safety['reported_conflict_on_consistent_inputs']+=1
    n=safety['inputs']
    return {'completed_BOMs':done,'total_BOMs':total,'full_population_complete':done==total,'execution_errors':errors,
        'all_BOMs_latent_asset_mapping_metrics':metrics(all_counts),
        'consistent_inputs_mapping_metrics':metrics(recoverable),'by_scenario':{k:metrics(v) for k,v in groups.items()},
        'by_fold_all_BOMs':{k:metrics(v) for k,v in folds.items()},
        'agent_stage_statuses':dict(stages),'wrong_input_safety':{**dict(safety),
            'reported_conflict_percent':100*safety['reported_conflicts']/n if n else None,
            'deferral_percent':100*safety['deferred_without_confirmed_mapping']/n if n else None},
        'interpretation':'Every BOM is executed and counted. All-BOM recall is against the latent true asset, including deliberately contradictory inputs. Consistent-input metrics cover controls and masks; wrong inputs also have conflict/unsafe-acceptance diagnostics. Unknown NVD applicability remains unjudged.'}
