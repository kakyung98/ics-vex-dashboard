"""Nominal, unweighted Cohen kappa over aligned pre-adjudication units."""
from collections import Counter, defaultdict
import random


def cohen_kappa(left, right):
    if len(left) != len(right):
        raise ValueError('Rating vectors must have identical aligned lengths.')
    if any(not isinstance(v, str) or not v.strip() for v in left + right):
        raise ValueError('Use explicit categorical labels; missing ratings are not a category.')
    n = len(left)
    if not n:
        return {'n': 0, 'kappa': None, 'raw_agreement': None, 'expected_agreement': None,
                'undefined_reason': 'no_paired_ratings', 'confusion': [], 'marginals': {'a': {}, 'b': {}}}
    a, b = Counter(left), Counter(right)
    confusion = Counter(zip(left, right))
    observed = sum(x == y for x, y in zip(left, right)) / n
    expected = sum(a[k] * b[k] for k in a.keys() | b.keys()) / (n * n)
    return {'n': n, 'kappa': (observed - expected) / (1 - expected) if expected < 1 else None,
            'raw_agreement': observed, 'expected_agreement': expected,
            'undefined_reason': 'single_identical_category' if expected == 1 else None,
            'confusion': [{'a': x, 'b': y, 'count': count} for (x, y), count in sorted(confusion.items())],
            'marginals': {'a': dict(a), 'b': dict(b)}}


def agreement_report(left, right, *, bootstrap=1000, seed=42):
    if bootstrap < 0:
        raise ValueError('Bootstrap repetitions cannot be negative.')
    def index(rows):
        result = {}; raters = set()
        for r in rows:
            required = ('unit_id', 'case_id', 'group_id', 'split', 'task', 'dimension', 'rater_id', 'rater_kind', 'phase')
            if any(not isinstance(r.get(k), str) or not r[k].strip() for k in required):
                raise ValueError('Every rating requires stable unit/case/group/task metadata and rater identity.')
            if r['unit_id'] in result:
                raise ValueError('Duplicate unit ID: ' + r['unit_id'])
            if r['phase'] != 'independent' or r['rater_kind'] not in {'human', 'model'}:
                raise ValueError('Use independent pre-adjudication human/model ratings only.')
            if r.get('label') is not None and (not isinstance(r['label'], str) or not r['label'].strip()):
                raise ValueError('Labels must be nonempty strings or null for missing.')
            raters.add((r['rater_id'], r['rater_kind']));result[r['unit_id']] = r
        if len(raters) > 1:
            raise ValueError('Each file must represent exactly one rater, not pooled reviewers.')
        return result, next(iter(raters), None)
    a, ra = index(left); b, rb = index(right)
    if ra and rb and ra[0] == rb[0]:
        raise ValueError('Two distinct raters are required.')
    if ra and rb and ra[1] != rb[1]:
        raise ValueError('Report human and model agreement separately; do not mix rater kinds.')
    strata = defaultdict(list);missing = 0; unmatched = sorted(set(a) ^ set(b))
    for key in sorted(a.keys() & b.keys()):
        x, y = a[key], b[key]
        if any(x[k] != y[k] for k in ('case_id', 'group_id', 'split', 'task', 'dimension')):
            raise ValueError('Annotation unit metadata mismatch: ' + key)
        if x.get('label') is None or y.get('label') is None:
            missing += 1
            continue
        strata[x['task'], x['dimension'], x['split']].append((x, y))
    reports = []
    for (task, dimension, split), pairs in sorted(strata.items()):
        score = cohen_kappa([x['label'] for x, _ in pairs], [y['label'] for _, y in pairs])
        clusters = defaultdict(list)
        for x, y in pairs:
            clusters[x['group_id']].append((x['label'], y['label']))
        values = [];undefined = 0;rng = random.Random(seed);keys = sorted(clusters)
        if len(keys) >= 2:
            for _ in range(bootstrap):
                sampled = [pair for k in rng.choices(keys, k=len(keys)) for pair in clusters[k]]
                value = cohen_kappa([x for x, _ in sampled], [y for _, y in sampled])['kappa']
                if value is None:undefined += 1
                else:values.append(value)
        values.sort()
        ci = [values[int((len(values)-1)*p)] for p in (.025, .975)] if values else None
        reports.append({'task': task, 'dimension': dimension, 'split': split, **score,
                        'group_count': len(keys), 'bootstrap': {'unit': 'group_id', 'seed': seed,
                        'requested': bootstrap, 'valid': len(values), 'undefined': undefined,
                        'percentile95_conditional_on_defined': ci,
                        'warning': 'Interpret with label marginals and undefined-resample count; small/degenerate strata may be unstable.'}})
    n = sum(r['n'] for r in reports)
    return {'schema': 'ics-vex-reviewer-agreement/1', 'status': 'computed' if n else 'not_evaluated',
            'agreement_kind': ('human_inter_rater' if ra[1] == 'human' else 'cross_model') if ra and rb else None,
            'raters': [ra, rb], 'paired_units': n, 'missing_rating_pairs': missing,
            'unmatched_unit_ids': unmatched, 'strata': reports, 'adjudicated_labels_used': False,
            'nominal_unweighted': True, 'gold_correctness_established': False,
            'independence_note': 'Separate identities do not verify reviewer blinding or independence.'}
