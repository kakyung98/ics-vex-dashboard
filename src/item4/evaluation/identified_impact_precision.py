"""Precision of an entire identified candidate set, irrespective of VEX output.

The caller freezes candidates before consulting impact labels. Unknown labels
remain in the population and give bounds rather than becoming false negatives.
"""


def score(labels, threshold=.85):
    tp=fp=unknown=0
    for label in labels:
        if label is True:tp+=1
        elif label is False:fp+=1
        elif label is None:unknown+=1
        else:raise ValueError('Impact gold must be true, false or null.')
    total=tp+fp+unknown
    precision=tp/total if total and not unknown else None
    return dict(identified_positives=total,TP=tp,FP=fp,unknown_impact=unknown,
        identified_cves=total,confirmed_exploitable=tp,confirmed_not_exploitable=fp,
        unknown_exploitability=unknown,
        confirmed_exploitable_fraction=tp/total if total else None,
        exploitability_fraction=precision,
        exploitability_fraction_bounds=[tp/total,(tp+unknown)/total] if total else None,
        precision=precision,precision_percent=100*precision if precision is not None else None,
        judged_only_precision=tp/(tp+fp) if tp+fp else None,
        gold_coverage=(tp+fp)/total if total else None,
        precision_bounds=[tp/total,(tp+unknown)/total] if total else None,
        target_percent=100*threshold,target_operator='>',target_met=precision>threshold if precision is not None else None,
        denominator='All identified candidates, before operational VEX filtering',
        unknown_policy='Retain unknowns in the full population; never score them as false or silently exclude them.')


def score_identified_cves(predictions, assessments=()):
    """Freeze unique SBOM/component/CVE outputs before joining impact truth.

    Repeated output rows do not increase the denominator. The same CVE on two
    components/assets is evaluated separately because its environment differs.
    Only explicit Boolean actual_exploitable labels resolve a candidate; model
    VEX statuses, missing assessments and errors never shrink the denominator.
    """
    candidates=set()
    for row in predictions:
        for component in row.get('component_predictions', []):
            for cve in component.get('confirmed_cves', []):
                candidates.add((row['id'],component['component_ref'],cve))
    truth={}
    for row in assessments:
        key=(row['sbom_id'],row['component_ref'],row['cve'])
        if key not in candidates:
            raise ValueError('Assessment outside the identified CVE population: '+str(key))
        if key in truth:
            raise ValueError('Duplicate exploitability assessment: '+str(key))
        value=row.get('actual_exploitable')
        if value is not None and type(value) is not bool:
            raise ValueError('actual_exploitable must be true, false or null.')
        truth[key]=value
    result=score(truth.get(key) for key in candidates)
    result.update(metric='exploitable_identified_cves / all_identified_cves',
        unit='SBOM ID × component-ref × CVE ID',
        unique_cve_ids=len({key[2] for key in candidates}),
        assessed_candidates=len(truth),
        interpretation='Fraction of the frozen identified CVE population verified exploitable in its asset context; not affected-output classifier precision.')
    return result


def controlled_truth(world):
    """Explicit hypothetical physical state, not source extraction or a verdict.

    These factors define this simulator only. They do not assert that every
    real CVE has the same requirements, or authenticate any field observation.
    """
    required=('component_deployed','cve_vulnerable_implementation_present',
              'complete_exploitation_route_active','required_actor_control_available',
              'effective_inline_protection')
    if any(type(world.get(k)) is not bool for k in required):
        raise ValueError('Controlled worlds require five explicit Boolean physical facts.')
    return all(world[k] for k in required[:-1]) and not world[required[-1]]
