"""Gold provenance, coverage-aware independent evaluation and GPU train admission."""
from collections import Counter
from pathlib import Path
import json
import random

from src.research.item4_stage1 import _index, _verify_ref, validate_bundle, validate_extraction
from src.research.item4_stage1_contracts import validate


def _score(gold, predicted):
    tp = len(gold & predicted)
    return dict(true_positive=tp, false_positive=len(predicted - gold),
                false_negative=len(gold - predicted), gold=len(gold), predicted=len(predicted),
                precision=tp / len(predicted) if predicted else None,
                recall=tp / len(gold) if gold else None,
                f1=2 * tp / (len(gold) + len(predicted)) if gold or predicted else None)


def evaluate_claims(bundle, extraction, gold, exported=None, bootstrap_samples=1000):
    validate_bundle(bundle); validate_extraction(bundle, extraction); validate('gold', gold)
    if gold['bundle_sha256'] != bundle['bundle_sha256']:
        raise ValueError('Gold source bundle mismatch')
    if bootstrap_samples < 1:
        raise ValueError('bootstrap_samples must be positive')
    segs = _index(bundle['segments'], 'segment')
    annotations = gold['segments']
    if not annotations or len({r['segment_id'] for r in annotations}) != len(annotations):
        raise ValueError('Empty or duplicate Gold segment annotations')
    resolved, ambiguous, expected = set(), set(), []
    for row in annotations:
        if row['segment_id'] not in segs:
            raise ValueError('Unknown Gold source segment')
        (resolved if row['adjudication'] == 'resolved' else ambiguous).add(row['segment_id'])
        for claim in row['conditions']:
            segment = _verify_ref(claim['evidence'], segs)
            if segment['id'] != row['segment_id']:
                raise ValueError('Gold evidence outside annotation segment')
            if claim['cve'] is not None and claim['cve'] not in bundle['population']:
                raise ValueError('Gold CVE outside population')
            if any(p not in {r['id'] for r in bundle['products']} for p in claim['product_ids']):
                raise ValueError('Unknown Gold product')
            if row['adjudication'] == 'resolved' and claim['role'] == 'necessary_condition':
                expected.append(claim)

    def key(claim):
        ref = claim['evidence'][0] if isinstance(claim['evidence'], list) else claim['evidence']
        return (ref['segment_id'], ref['start'], ref['end'], claim['role'],
                claim['cve'], tuple(sorted(claim['product_ids'])))

    truth = {key(c) for c in expected}
    if len(truth) != len(expected):
        raise ValueError('Duplicate Gold conditions')
    predictions = [c for c in extraction['candidates'] if c['role'] == 'necessary_condition']

    def score(rows):
        scored = [c for c in rows if c['evidence'][0]['segment_id'] in resolved]
        guessed = {key(c) for c in scored}
        result = _score(truth, guessed)
        result['duplicate_predictions'] = len(scored) - len(guessed)
        result['ambiguous_segment_predictions'] = sum(c['evidence'][0]['segment_id'] in ambiguous for c in rows)
        # Exact claim mismatch does not automatically mean unsupported meaning.
        result['unmatched_claims'] = [c['id'] for c in scored if key(c) not in truth]
        result['unmatched_claims_require_error_adjudication'] = True
        return result, guessed

    candidate_score, guessed = score(predictions)
    grouped = {}
    for sid in resolved:
        grouped.setdefault(segs[sid]['source_id'], set()).add(sid)
    ci = None
    if len(grouped) >= 2:
        rng = random.Random(42); sources = sorted(grouped); samples = []
        for _ in range(bootstrap_samples):
            tp = denom = 0
            for source in rng.choices(sources, k=len(sources)):
                ids = grouped[source]
                g = {k for k in truth if k[0] in ids}; p = {k for k in guessed if k[0] in ids}
                tp += len(g & p); denom += len(p)
            if denom:
                samples.append(tp / denom)
        if samples:
            samples.sort()
            ci = dict(method='source_document_cluster_bootstrap', seed=42, samples=bootstrap_samples,
                      defined_samples=len(samples), low=samples[int(.025 * (len(samples)-1))],
                      high=samples[int(.975 * (len(samples)-1))],
                      warning='Zero observed errors may yield a degenerate interval; this is not proof of zero population error.')
    approved = None
    if exported is not None:
        from src.item4.analysis.advisory_source_bundles import verify_seal
        verify_seal(exported, 'export_sha256')
        if exported['bundle_sha256'] != bundle['bundle_sha256'] or exported['extraction_sha256'] != extraction['extraction_sha256']:
            raise ValueError('Export provenance mismatch')
        approved, _ = score([r['claim'] for r in exported['accepted'] if r['claim']['role'] == 'necessary_condition'])
    return dict(metric='exact_span_role_CVE_product_scope_claim_match',
                independent_gold_provenance='supplied_human_assertion_not_authenticated',
                candidate=candidate_score, accepted=approved,
                candidate_precision_interval=ci, source_document_groups=len(grouped),
                population_cves=len(bundle['population']), all_segments=len(segs),
                annotated_segments=len(annotations), resolved_segments=len(resolved),
                ambiguous_segments=len(ambiguous), unannotated_segments=len(segs)-len(annotations),
                processing_statuses=dict(Counter(r['status'] for r in extraction['processing_ledger'] if r['segment_id'] in resolved)),
                warning='Exact-match errors need semantic adjudication; this metric is not an automatic unsupported-extraction rate.')


def training_readiness(paths):
    """Check independent, declared human provenance; do not fabricate missing labels."""
    from src.research.item4_stage1_spans import check_splits
    rows, errors = {}, []
    for split, filename in paths.items():
        try:
            with Path(filename).open(encoding='utf-8-sig') as stream:
                rows[split] = [json.loads(line) for line in stream if line.strip()]
        except (OSError, ValueError) as exc:
            rows[split] = []; errors.append(f'{split}: {type(exc).__name__}')
        if not rows[split]:
            errors.append(f'{split}: no annotated documents')
        for row in rows[split]:
            if row.get('annotation_origin') != 'human' or row.get('model_predictions_seen') is not False:
                errors.append(f'{split}/{row.get("id")}: independent human provenance missing')
            if not row.get('source_document_sha256') or not row.get('source_file'):
                errors.append(f'{split}/{row.get("id")}: original source provenance missing')
    if not errors:
        try:
            check_splits(rows['train'], rows['dev'], rows['test'])
            from src.item4.analysis.advisory_source_bundles import resolve_pointer
            import hashlib
            for split_rows in rows.values():
                for row in split_rows:
                    raw = Path(row['source_file']).read_bytes()
                    if hashlib.sha256(raw).hexdigest() != row['source_document_sha256']:
                        raise ValueError('Training original source hash mismatch')
                    if resolve_pointer(json.loads(raw.decode('utf-8-sig')), row['source_json_pointer']) != row['text']:
                        raise ValueError('Training original text mismatch')
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(str(exc))
    return dict(ready=not errors, errors=errors, documents={k:len(v) for k,v in rows.items()},
                human_identity_authenticated=False,
                training_device_policy='H200 CUDA only; no local training fallback'), rows
