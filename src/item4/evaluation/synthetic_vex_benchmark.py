"""Conditional synthetic CSAF scenarios and independent expert agreement.

Candidate labels are never expert gold. This module does not change production
VEX decisions or turn an operational network control into a product VEX flag.
"""
from collections import Counter
import hashlib
import json
import math
import random

VERSION = 'item4-csaf-expert/2'
JUSTIFICATIONS = (
    'component_not_present', 'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
)
VARIANTS = JUSTIFICATIONS + ('affected_control', 'insufficient_evidence')
STATUSES = ('affected', 'not_affected', 'under_investigation')
FACTS = (
    'component_present', 'vulnerable_code_present', 'execution_path_exists',
    'adversary_control_possible', 'inline_protection_effective',
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def reference(facts):
    """A closed-world hypothetical product, not a real-CVE exploit oracle."""
    c, v, e, a, m = (facts.get(k) for k in FACTS)
    if c is False:
        return False
    if c is True and v is False:
        return False
    if c is True and v is True and e is False:
        return False
    if c is True and v is True and e is True and a is False:
        return False
    if c is True and v is True and e is True and a is True and m is True:
        return False
    if all(x is True for x in (c, v, e, a)) and m is False:
        return True
    return None


def scenario(variant, source_bound):
    if variant not in VARIANTS:
        raise ValueError('Unknown variant')
    facts = dict.fromkeys(FACTS)
    # One reason at a time: later facts are irrelevant and stay unknown.
    position = VARIANTS.index(variant)
    if position < 5:
        for key in FACTS[:position]:
            facts[key] = True
        facts[FACTS[position]] = (position == 4)
    elif variant == 'affected_control':
        facts.update(dict.fromkeys(FACTS[:4], True))
        facts[FACTS[4]] = False
    # Unbound source paths cannot supply an invented CVE-specific relationship.
    supported = source_bound or variant == 'component_not_present'
    actual = reference(facts) if supported else None
    status = ('under_investigation' if actual is None else
              'affected' if actual else 'not_affected')
    return dict(facts=facts, candidate_actual_affected=actual,
                candidate_status=status,
                candidate_justifications=[variant] if status == 'not_affected' else [],
                source_relationship_available=bool(source_bound),
                conditional_only=True)


def kappa(pairs):
    """Unweighted nominal Cohen kappa; undefined marginals remain undefined."""
    pairs = list(pairs)
    n = len(pairs)
    if not n:
        return dict(n=0, observed_agreement=None, chance_agreement=None, kappa=None)
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    po = sum(a == b for a, b in pairs) / n
    pe = sum(left[k] * right[k] for k in left.keys() | right.keys()) / (n * n)
    value = (po - pe) / (1 - pe) if pe < 1 else None
    return dict(n=n, observed_agreement=po, chance_agreement=pe, kappa=value,
                confusion={a: dict(Counter(b for x, b in pairs if x == a)) for a in sorted(left)},
                left_counts=dict(left), right_counts=dict(right))


def agreement(rows, field, bootstrap=1000, seed=20261120):
    """Resample advisory clusters, preserving within-advisory dependence."""
    groups = {}
    for row in rows:
        a, b = row['a'].get(field), row['b'].get(field)
        if a is not None and b is not None:
            groups.setdefault(row['advisory_id'], []).append((str(a), str(b)))
    result = kappa(p for group in groups.values() for p in group)
    result['clusters'] = len(groups)
    result['missing_pairs'] = len(rows) - result['n']
    keys, values = sorted(groups), []
    rng = random.Random(seed)
    if len(keys) > 1:
        for _ in range(bootstrap):
            sampled = (p for key in rng.choices(keys, k=len(keys)) for p in groups[key])
            value = kappa(sampled)['kappa']
            if value is not None and math.isfinite(value):
                values.append(value)
    values.sort()
    result['ci95'] = ([values[int(.025 * (len(values)-1))], values[int(.975 * (len(values)-1))]]
                      if values else None)
    result['bootstrap_valid_replicates'] = len(values)
    return result


def affected_precision(predictions, gold):
    """Preserve TP/(TP+FP), strict >85%, unknown-positive blocking."""
    if set(predictions) != set(gold):
        raise ValueError('Predictions must cover the entire requested population; missing/extra IDs')
    tp = fp = unjudged = fn = abstentions = 0
    for key, prediction in predictions.items():
        status = prediction['status']
        if status not in STATUSES:
            raise ValueError('Invalid prediction status')
        actual = gold[key]['actual_affected']
        if actual is not None and type(actual) is not bool:
            raise ValueError('Gold actual_affected must be Boolean or null')
        affected = status == 'affected'
        tp += affected and actual is True
        fp += affected and actual is False
        unjudged += affected and actual is None
        fn += not affected and actual is True
        abstentions += status == 'under_investigation'
    precision = tp / (tp + fp) if tp + fp and not unjudged else None
    return dict(n=len(gold), TP=tp, FP=fp, FN=fn, unjudged_predicted_affected=unjudged,
                precision=precision, precision_percent=100*precision if precision is not None else None,
                target_met=precision > .85 if precision is not None else None,
                recall=tp/(tp+fn) if tp+fn else None,
                abstention_rate=abstentions/len(gold) if gold else None,
                formula='TP/(TP+FP)', strict_threshold=.85)


def csaf_vex(case_id, cve, product, status, justifications, statement):
    if status not in STATUSES or any(j not in JUSTIFICATIONS for j in justifications):
        raise ValueError('Invalid CSAF status/justification')
    if (status == 'not_affected') != bool(justifications):
        raise ValueError('Only not_affected carries one or more justifications')
    pid = 'CSAFPID-' + digest([case_id, product])[:16]
    status_key = {'affected':'known_affected', 'not_affected':'known_not_affected',
                  'under_investigation':'under_investigation'}[status]
    at = '2026-11-20T00:00:00Z'
    vulnerability = dict(cve=cve, product_status={status_key:[pid]},
                         threats=[dict(category='impact', details=statement, product_ids=[pid])])
    if justifications:
        vulnerability['flags'] = [dict(label=j, product_ids=[pid]) for j in justifications]
    return dict(document=dict(category='csaf_vex', csaf_version='2.0',
        title='Synthetic benchmark VEX draft ' + case_id,
        publisher=dict(category='other', name='ICS-VEX synthetic benchmark',
                       namespace='https://example.invalid/ics-vex-benchmark'),
        distribution=dict(tlp=dict(label='WHITE')),
        tracking=dict(id=case_id, status='draft', version='1', initial_release_date=at,
                      current_release_date=at,
                      revision_history=[dict(number='1', date=at, summary='Conditional synthetic draft; not a supplier advisory')])),
        product_tree=dict(full_product_names=[dict(name=product, product_id=pid)]),
        vulnerabilities=[vulnerability])
