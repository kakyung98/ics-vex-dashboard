"""Offline stage-1 source preparation, extractive candidates and review gates.

Never trains locally. The train command requires an H200 CUDA device and
independently declared human source annotations before loading model weights.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.research.item4_stage1 import (candidate, export_claims, extraction_report, propose_rules,
                             review_template, validate_bundle, validate_extraction)
from src.item4.analysis.advisory_source_bundles import VERSION; from src.item4.analysis.advisory_source_bundles import audit_sources; from src.item4.analysis.advisory_source_bundles import build_bundle; from src.item4.analysis.advisory_source_bundles import seal


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def collect(inputs):
    paths = []
    for name in inputs:
        p = Path(name)
        paths.extend(sorted(p.glob('*.json')) if p.is_dir() else [p])
    return sorted(set(paths))


def population(path):
    if path is None:
        return None
    value = read(path)
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get('advisories'), list):
        return sorted({c for r in value['advisories'] for c in r['declared_cves']})
    raise ValueError('Population must be a CVE ID array or advisory index with declared_cves')


def bert_proposals(bundle, checkpoint, device='cuda', max_length=512, stride=64):
    """BERT predicts exact spans; no rule fallback hidden as learned output."""
    from src.research.item4_stage1_bert import BertExtractor
    model = BertExtractor(checkpoint, device=device, local_files_only=True)
    documents = {d['id']:d for d in bundle['documents']}
    claims, ledger = [], []
    for segment in bundle['segments']:
        s = segment
        row = dict(id=s['id'], source_id=s['source_id'], source_type='ICSA' if documents[s['source_id']]['kind'] == 'ICSA_CSAF' else 'CVE',
                   group_id=s['source_id'], text=s['text'], text_sha256=s['text_sha256'],
                   cves=s['cves'], spans=[], annotation_complete=False)
        try:
            prediction = model.predict(row, max_length, stride)
            proposed = [candidate(bundle, s, span['start'], span['end'], span['role'], 'bert:' + str(checkpoint))
                        for span in prediction['spans']]
            claims.extend(proposed)
            ledger.append(dict(segment_id=s['id'], status='processed_with_candidates' if proposed else 'processed_no_candidate',
                               candidate_ids=[c['id'] for c in proposed], full_segment_examined=True,
                               semantic_accuracy_verified=False))
        except (ValueError, RuntimeError):
            ledger.append(dict(segment_id=s['id'], status='inference_failed', candidate_ids=[],
                               full_segment_examined=False, semantic_accuracy_verified=False))
    return seal(dict(contract_version=VERSION, bundle_sha256=bundle['bundle_sha256'], method='bert:' + str(checkpoint),
                     candidates=claims, processing_ledger=ledger, logic=None,
                     coverage_complete=False, vex_eligible=False, semantic_accuracy_verified=False), 'extraction_sha256')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--input', nargs='+', required=True)
    p.add_argument('--population'); p.add_argument('--output', required=True)
    p.add_argument('--expected-advisories', help='Index of expected CSAF files, including missing sources')
    p = sub.add_parser('schemas'); p.add_argument('--output', required=True)
    for name in ('propose', 'review-template', 'export', 'audit', 'evaluate'):
        p = sub.add_parser(name); p.add_argument('--bundle', required=True); p.add_argument('--output', required=True)
        if name in ('review-template', 'export', 'evaluate'):
            p.add_argument('--extraction', required=True)
        if name == 'propose':
            p.add_argument('--method', choices=['rules', 'bert'], default='rules')
            p.add_argument('--checkpoint'); p.add_argument('--device', default='cuda')
        if name == 'export': p.add_argument('--reviews', required=True)
        if name == 'evaluate':
            p.add_argument('--gold', required=True); p.add_argument('--exported')
    for name in ('train-readiness', 'train'):
        p = sub.add_parser(name)
        for split in ('train', 'dev', 'test'):
            p.add_argument('--' + split, required=True)
        p.add_argument('--output', required=True)
        if name == 'train':
            p.add_argument('--base-model', required=True); p.add_argument('--epochs', type=int, default=3)
            p.add_argument('--batch-size', type=int, default=16)
    args = parser.parse_args(argv)
    if args.command == 'schemas':
        from src.research.item4_stage1_contracts import schemas
        for name, value in schemas().items(): write(Path(args.output) / (name + '.schema.json'), value)
        return
    if args.command == 'prepare':
        paths = collect(args.input)
        if args.expected_advisories:
            if len(args.input) != 1 or not Path(args.input[0]).is_dir():
                raise ValueError('--expected-advisories requires exactly one CSAF input directory')
            paths = sorted(set(paths) | {Path(args.input[0]) / (r['advisory_id'] + '.json')
                                         for r in read(args.expected_advisories)['advisories']})
        bundle = build_bundle(paths, population(args.population))
        validate_bundle(bundle); write(args.output, bundle)
        print(json.dumps(dict(documents=len(bundle['documents']), segments=len(bundle['segments']), population=len(bundle['population']))))
        return
    if args.command in ('train-readiness', 'train'):
        from src.research.item4_stage1_evaluation import training_readiness
        result, rows = training_readiness({k:getattr(args, k) for k in ('train', 'dev', 'test')})
        if args.command == 'train-readiness':
            write(args.output, result); print(json.dumps(result)); return
        if not result['ready']:
            raise ValueError('Training blocked: ' + '; '.join(result['errors'][:8]))
        import torch
        if not torch.cuda.is_available() or 'H200' not in torch.cuda.get_device_name(0):
            raise ValueError('Training is restricted to H200; no local/CPU fallback')
        from src.common.gpu_lease import assert_inference_available
        assert_inference_available()
        from src.research.item4_stage1_bert import train
        train(rows['train'], rows['dev'], rows['test'], args.base_model, args.output,
              epochs=args.epochs, batch_size=args.batch_size, device='cuda', local_files_only=True)
        return
    bundle = read(args.bundle)
    if args.command == 'audit':
        validate_bundle(bundle)
        report = audit_sources(bundle); write(args.output, report)
        if not report['passed']: raise ValueError('Original source audit failed')
        return
    if args.command == 'propose':
        if args.method == 'bert' and not args.checkpoint:
            raise ValueError('--checkpoint required for BERT; no implicit model fallback')
        result = propose_rules(bundle) if args.method == 'rules' else bert_proposals(bundle, args.checkpoint, args.device)
        validate_extraction(bundle, result); write(args.output, result)
        return
    extraction = read(args.extraction)
    if args.command == 'review-template':
        validate_extraction(bundle, extraction)
        write(args.output, [review_template(c) for c in extraction['candidates']]); return
    if args.command == 'export':
        audit = audit_sources(bundle)
        if not audit['passed']: raise ValueError('Cannot export without matching original source bytes')
        result = export_claims(bundle, extraction, read(args.reviews)); write(args.output, result)
        print(json.dumps(extraction_report(bundle, extraction, result))); return
    if args.command == 'evaluate':
        from src.research.item4_stage1_evaluation import evaluate_claims
        write(args.output, evaluate_claims(bundle, extraction, read(args.gold), read(args.exported) if args.exported else None))


if __name__ == '__main__':
    main()
