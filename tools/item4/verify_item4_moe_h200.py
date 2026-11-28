"""Compare 33 frozen scenarios on the serial and batched v2 runtime and their earlier receipts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.models.expert_batch_inference import generate_candidates
from src.item4.models.remote_gpu_expert_client import H200Batch


SAMPLES = ('moe-20261121T112525Z-6d4b3c7e6c38', 'moe-20261121T112702Z-99e3a1e11d83')
CASE_FIELDS = ('id', 'cve', 'version', 'input_sha256', 'candidate_status', 'generation_status',
               'routed_experts', 'reasons', 'product_reasons', 'evidence_ids', 'cited_evidence')
EXPERT_FIELDS = ('expert', 'input_sha256', 'verdict', 'evidence_ids', 'offered_conflict_group',
                 'reason_code', 'error_kind', 'model')


def comparison(baseline, current):
    mismatches = []
    counts = Counter()
    matched_experts = 0
    for old, new in zip(baseline, current, strict=True):
        case = old['id']
        assert new['id'] == case
        fields = [field for field in CASE_FIELDS if old.get(field) != new.get(field)]
        for field in fields:
            counts[field] += 1
        if fields:
            mismatches.append(dict(case=case, fields=fields))
        left = {e['expert']: e for e in old['experts']}
        right = {e['expert']: e for e in new['experts']}
        for name in sorted(left.keys() | right.keys()):
            if name not in left or name not in right:
                mismatches.append(dict(case=case, expert=name, fields=['routing']))
                continue
            fields = [field for field in EXPERT_FIELDS if left[name].get(field) != right[name].get(field)]
            if fields:
                mismatches.append(dict(case=case, expert=name, fields=fields))
            else:
                matched_experts += 1
    return dict(passed=not mismatches, cases=len(current), matched_expert_receipts=matched_experts,
                mismatched_case_field_counts=dict(counts), mismatches=mismatches)


def reference_runs():
    for run_id in SAMPLES:
        root = runs.OUTPUT / run_id
        report = json.loads((root / 'report.json').read_bytes())
        assert report['ledger']['status'] == 'completed'
        assert runs.file_sha(root / 'candidates.jsonl') == report['candidates_sha256']
        yield report, list(map(json.loads, (root / 'candidates.jsonl').read_bytes().splitlines()))


def verified_inputs():
    base = json.loads(runs.BASELINE.read_bytes())
    folder = Path(base['artifact_directory'])
    pin = json.loads((runs.REPLAY / 'report.json').read_bytes())['source_manifest_sha256']
    manifest = runs.sealed_json(folder / 'delivery_manifest.json', pin)
    items, archived = [], []
    for report, reference in reference_runs():
        for cve in report['selected_cves']:
            packet = runs.input_packet(folder, manifest, cve)
            product, rule = runs.scoped_inputs(packet)
            items.extend((runs.scenario_input(case, product), product, rule) for case in packet['cases'])
        archived.extend(reference)
    assert len(items) == len(archived) == len({r['id'] for r in archived}) == 33
    return items, archived


def execute(remote, endpoint, items):
    wire = {}
    timings = []
    def provider(requests):
        body = dict(runtime_sha256=remote.identity['runtime_sha256'], requests=requests)
        start = perf_counter()
        response = remote.session.post(remote.url + endpoint, json=body, timeout=(10, 600))
        response.raise_for_status()
        reply = response.json()
        assert reply['runtime_sha256'] == remote.identity['runtime_sha256']
        elapsed = perf_counter() - start
        outputs = reply['outputs']
        assert len(requests) == len(outputs)
        timings.append(dict(requests=len(requests), seconds=round(elapsed, 3)))
        for request, output in zip(requests, outputs):
            assert output['llm_used'] is True
            raw = json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode()
            wire[hashlib.sha256(raw).hexdigest()] = output
        return outputs
    start = perf_counter()
    candidates = generate_candidates(items, cache={}, batch_size=128, provider=provider)
    elapsed = round(perf_counter() - start, 3)
    print(endpoint, len(wire), 'model requests', elapsed, 'seconds', flush=True)
    return candidates, wire, dict(seconds=elapsed, requests=len(wire), waves=timings)


def verify(port, output):
    remote = H200Batch(port)
    items, archived = verified_inputs()
    batch, batch_wire, batch_perf = execute(remote, '/batch', items)
    archive_batch = comparison(archived, batch)
    print('archived vs H200 batch:', json.dumps(archive_batch), flush=True)
    serial, serial_wire, serial_perf = execute(remote, '/serial', items)
    keys = serial_wire.keys() | batch_wire.keys()
    mismatches = [key for key in sorted(keys) if key not in serial_wire or key not in batch_wire
                  or serial_wire[key]['prediction'] != batch_wire[key]['prediction']]
    with_raw = sorted(key for key in serial_wire.keys() & batch_wire.keys()
                      if 'raw' in serial_wire[key] and 'raw' in batch_wire[key])
    raw_differences = [key for key in with_raw if batch_wire[key]['raw'] != serial_wire[key]['raw']]
    with_lengths = sorted(key for key in serial_wire.keys() & batch_wire.keys()
                          if 'generation' in serial_wire[key] and 'generation' in batch_wire[key])
    length_differences = [key for key in with_lengths if any(batch_wire[key]['generation'].get(k)
        != serial_wire[key]['generation'].get(k) for k in ('input_tokens', 'output_tokens'))]
    comparisons = dict(h200_serial_vs_batch=comparison(serial, batch), archived_vs_h200_batch=archive_batch,
                       archived_vs_h200_serial=comparison(archived, serial))
    result = dict(passed=not (mismatches or raw_differences or length_differences)
                  and all(c['passed'] for c in comparisons.values()), source_runs=list(SAMPLES),
                  device=remote.identity['device'], runtime=remote.identity,
                  comparisons=comparisons, expert_requests=dict(distinct=len(keys), mismatches=mismatches,
                      raw_output_comparisons=len(with_raw), raw_output_mismatches=raw_differences,
                      token_length_comparisons=len(with_lengths), token_length_mismatches=length_differences),
                  performance=dict(batch=batch_perf, serial=serial_perf, order=['batch','serial']))
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('passed:', result['passed'], 'artifact:', output, flush=True)
    return result['passed']


def check_population(run_id, output=None):
    import re
    if not re.fullmatch(r'moe-\d{8}T\d{6}Z-[a-f0-9]{12}', run_id):
        raise ValueError('Invalid run ID')
    directory = runs.OUTPUT / run_id
    summary = json.loads((directory / 'report.json').read_bytes())
    archived = [row for _, rows in reference_runs() for row in rows]
    wanted = {r['id'] for r in archived}
    digest = hashlib.sha256()
    matched = {}
    with (directory / 'candidates.jsonl').open('rb') as source:
        for line in source:
            digest.update(line)
            row = json.loads(line)
            if row['id'] in wanted:
                if row['id'] in matched or row['run_id'] != run_id:
                    raise ValueError('Duplicate or out-of-scope scenario in the population candidates')
                matched[row['id']] = row
    if digest.hexdigest() != summary['candidates_sha256'] or matched.keys() != wanted:
        raise ValueError('Population export digest or frozen sample coverage differs')
    result = dict(run_id=run_id, generation_status=summary['ledger']['status'], source_runs=list(SAMPLES),
                  population_candidates_sha256=digest.hexdigest(),
                  **comparison(archived, [matched[row['id']] for row in archived]))
    target = output or directory / 'frozen_33_case_replay.json'
    target.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18128)
    parser.add_argument('--population-run', help='Compare a published population export to the original 33 cases offline.')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    passed = (check_population(args.population_run, args.output) if args.population_run
              else verify(args.port, args.output or runs.OUTPUT / 'h200_v2_parity_20261121.json'))
    sys.exit(0 if passed else 1)
