"""Evaluate a revised supplier evidence contract on the closed v2 rejection and control cohorts."""
import argparse
from collections import Counter
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.models import scenario_review_experts as v2
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation import supplier_evidence_review as supplier
from src.item4.evaluation.bulk_scenario_runner import ExpertCache; from src.item4.evaluation.bulk_scenario_runner import atomic_json; from src.item4.evaluation.bulk_scenario_runner import encoded
from tools.item4.verify_item4_supplier_pilot import selected_rows
from tools.item4.item4_source_history import pinned_source


VERSION = 'item4-scenario-moe/2+supplier-review/1'
PARENT = runs.OUTPUT / 'moe-20261121T120040Z-d1c0719505bc'
OUTPUT = ROOT / 'results/item4_supplier_review_20261122'


def supplier_rows(product):
    distinct = {}
    for eid, row in v2._product_rows(product):
        distinct.setdefault((row['version_membership'], row['status']), (eid, row))
    return list(distinct.values())


def load_inputs(parent):
    chosen = selected_rows(parent)
    report = json.loads((parent / 'report.json').read_bytes())
    pins = report['ledger']['code_hashes']
    for filename, sha in pins.items():
        if filename.endswith('.py'):
            path = (ROOT if '/' in filename else ROOT / 'src') / filename
            pinned_source(path, sha)
    folder = Path(json.loads(runs.BASELINE.read_bytes())['artifact_directory'])
    manifest = runs.sealed_json(folder / 'delivery_manifest.json', report['ledger']['data_hashes']['v3 delivery manifest'])
    packets = {}
    items = []
    requests = {}
    for case_id, (cohort, row_sha, old) in sorted(chosen.items()):
        cve = old['cve']
        if cve not in packets:
            packet = runs.input_packet(folder, manifest, cve)
            product, rule = runs.scoped_inputs(packet)
            rows = supplier_rows(product)
            req = supplier.build_request(rows)
            packets[cve] = ({c['id']: c for c in packet['cases']}, product, rule, rows, req)
        cases, product, rule, rows, req = packets[cve]
        if (not rows or product != old['verified_product'] or old['packet_sha256'] !=
                manifest[f'{runs.PREFIX}/cves/{cve}.json'] or cases[case_id]['synthetic'] is not True):
            raise ValueError('The selected source or product evidence differs from the parent case.')
        wire = supplier.wire_sha256(req)
        requests[wire] = dict(wire_sha256=wire, **req)
        scenario = runs.scenario_input(cases[case_id], product)
        items.append((cohort, row_sha, old, scenario, product, rule, rows, wire))
    bundle = dict(contract_version=supplier.VERSION, parent_run_id=parent.name,
                  requests=[requests[key] for key in sorted(requests)])
    return items, bundle, report


def prepare(parent, output):
    items, bundle, _ = load_inputs(parent)
    output.mkdir(parents=True, exist_ok=True)
    path = output / 'requests.json'
    if path.exists():
        if path.read_text(encoding='utf-8') != json.dumps(bundle, ensure_ascii=False, indent=2):
            raise ValueError('Output directory already contains a different request bundle.')
    else:
        atomic_json(path, bundle)
    print(f'{len(items)} scenarios, {len(bundle["requests"])} distinct supplier requests, SHA-256 {runs.file_sha(path)}')


class ReviewResponses:
    """Bind the revised supplier answer and original model receipts to one blinded scenario."""

    def __init__(self, old, rows, wire, output, parent_cache, accepted):
        self.parent_experts = {e['expert']: e for e in old['experts']}
        self.wire = wire
        self.parent_cache = parent_cache
        self.accepted = accepted
        self.supplier_output = dict(output, prediction=supplier.resolve(rows, output['prediction']))
        self.error = None

    def request_model(self, key, system, packet):
        role = packet['expert']
        before = self.parent_experts.get(role)
        if before is None or before['wire_sha256'] != key[1]:
            self.error = 'Scenario routing or expert input differs from its sealed parent.'
            raise ValueError(self.error)
        if role == 'supplier':
            return self.supplier_output, self.wire in self.accepted
        cached = self.parent_cache[key]
        if before['execution'] not in {'model', 'cached'} or not cached.get('llm_used'):
            self.error = 'No validated parent model response for ' + role
            raise ValueError(self.error)
        return cached, True

    def __setitem__(self, key, value):
        # v2 calls this only after validating an actual, previously unused supplier result.
        if key[1] != self.parent_experts['supplier']['wire_sha256']:
            raise ValueError('Unexpected new response for a frozen expert.')
        self.accepted.add(self.wire)


def apply_response(item, run_id, outputs, parent_cache, accepted):
    cohort, row_sha, old, scenario, product, rule, rows, wire = item
    source = ReviewResponses(old, rows, wire, outputs[wire], parent_cache, accepted)
    candidate = v2.generate_candidate(scenario, product, condition_rule=rule, cache=source)
    if source.error or candidate['input_sha256'] != old['input_sha256']:
        raise ValueError(source.error or 'The reconstructed v2 scenario input differs.')
    if candidate['routed_experts'] != old['routed_experts']:
        raise ValueError('This bounded pilot requires the original non-supplier routes.')
    candidate['v2_input_sha256'] = candidate['input_sha256']
    candidate['input_sha256'] = v2.digest([VERSION, old['input_sha256'], wire])
    for expert in candidate['experts']:
        prior = source.parent_experts[expert['expert']]
        if any(expert[k] != prior[k] for k in ('wire_sha256', 'input_sha256')):
            raise ValueError('Scope or model input differs from the frozen parent.')
        if expert['expert'] == 'supplier':
            expert.update(v2_wire_sha256=expert['wire_sha256'], v2_scope_sha256=expert['input_sha256'],
                          contract_version=supplier.VERSION, response_source='pilot_supplier_model',
                          selection=outputs[wire]['prediction']['assessment'])
            expert['input_sha256'] = v2.digest([supplier.VERSION, wire, [eid for eid, _ in rows]])
            expert['wire_sha256'] = wire
        else:
            if expert['execution'] != 'cached' or any(expert[k] != prior[k] for k in ('verdict', 'evidence_ids', 'model')):
                raise ValueError('A replayed expert response differs from its original verdict or citation.')
            expert['response_source'] = 'parent_v2_model_cache'
    candidate.update(version=VERSION, cohort=cohort, parent_run_id=old['run_id'], parent_row_sha256=row_sha)
    return runs.bind_candidate(candidate, run_id, old['packet_sha256'], product, rule)


def validate_outputs(output, parent, report, bundle):
    path = output / 'requests.json'
    expected = json.dumps(bundle, ensure_ascii=False)
    if json.dumps(json.loads(path.read_bytes()), ensure_ascii=False) != expected:
        raise ValueError('Prepared model inputs differ from the current frozen selection.')
    receipt = json.loads((output / 'responses.json').read_bytes())
    outputs = receipt['responses']
    if (receipt['contract_version'] != supplier.VERSION or receipt['parent_run_id'] != parent.name
            or receipt['requests_sha256'] != runs.file_sha(path)
            or receipt['parent_candidates_sha256'] != report['candidates_sha256']
            or receipt['parent_report_sha256'] != runs.file_sha(parent / 'report.json')
            or receipt['model_identity'] != report['backend_identity']
            or receipt['worker_sha256'] != runs.file_sha(ROOT / 'tools/item4/run_item4_supplier_review_worker.py')
            or receipt['actual_model_calls'] != len(outputs)
            or set(outputs) != {r['wire_sha256'] for r in bundle['requests']}):
        raise ValueError('The serial model receipt differs from its input, model, code or parent pins.')
    for answer in outputs.values():
        if (answer['llm_used'] is not True or answer['model']['model'] != receipt['model_identity']['model']
                or answer['model']['adapter'] is not None or answer['model']['provider'] != 'local_shared_base'
                or answer['generation']['constrained_json'] is not True or answer['generation']['output_tokens'] < 1
                or json.loads(answer['raw']) != answer['prediction']):
            raise ValueError('A model response lacks its original constrained generation receipt.')
    return receipt


def distributions(rows):
    counts = ledger.ProgressCounts()
    for row in rows:
        counts.add(row)
    return counts.snapshot()


def evaluate(parent, output):
    items, bundle, baseline = load_inputs(parent)
    receipt = validate_outputs(output, parent, baseline, bundle)
    pins = {p.name: runs.file_sha(p) for p in (Path(__file__), ROOT / 'src/item4/evaluation/supplier_evidence_review.py',
                                                ROOT / 'tools/item4/run_item4_supplier_review_worker.py')}
    response_sha = runs.file_sha(output / 'responses.json')
    rid = 'moe-supplier-pilot-' + v2.digest([VERSION, parent.name, receipt['requests_sha256'], response_sha, pins])[:16]
    accepted = set()
    with closing(sqlite3.connect((parent / 'records.sqlite3').as_uri() + '?mode=ro', uri=True)) as db:
        cache = ExpertCache(db)
        rows = [apply_response(item, rid, receipt['responses'], cache, accepted) for item in items]
    raw = b''.join(encoded(row) + b'\n' for row in rows)
    results = output / 'pilot_candidates.jsonl'
    if results.exists() and results.read_bytes() != raw:
        raise ValueError('Existing pilot candidates differ. Select a new output directory.')
    tmp = results.with_suffix('.jsonl.tmp')
    tmp.write_bytes(raw)
    tmp.replace(results)
    cohorts = {}
    for name in ('failure', 'control'):
        subset = [r for r in rows if r['cohort'] == name]
        cohorts[name] = dict(scenarios=len(subset), cves=len({r['cve'] for r in subset}), **distributions(subset))
    differences = Counter(dict.fromkeys(('candidate_status','reasons','product_reasons','supplier_verdict',
                                        'supplier_evidence_ids','evidence_ids'), 0))
    experts = [e for r in rows for e in r['experts']]
    for item, row in zip(items, rows):
        if row['cohort'] == 'control':
            old = item[2]
            for field in ('candidate_status', 'reasons','product_reasons', 'evidence_ids'):
                differences[field] += row[field] != old[field]
            before = next(e for e in old['experts'] if e['expert'] == 'supplier')
            after = next(e for e in row['experts'] if e['expert'] == 'supplier')
            for field in ('verdict', 'evidence_ids'):
                differences['supplier_' + field] += before[field] != after[field]
    single = sum(len(r['packet']['schema']['properties']['assessment']['enum']) == 1 for r in bundle['requests'])
    report = dict(run_id=rid, version=VERSION, contract_version=supplier.VERSION, parent_run_id=parent.name,
                  parent_total=baseline['ledger']['total'], parent_candidates_sha256=baseline['candidates_sha256'],
                  candidates_sha256=runs.sha(raw), requests_sha256=receipt['requests_sha256'], responses_sha256=response_sha,
                  code_hashes=pins, actual_model_calls=receipt['actual_model_calls'], model_identity=receipt['model_identity'],
                  **distributions(rows), cohorts=cohorts, expert_executions=Counter(e['execution'] for e in experts),
                  parent_expert_receipts_reused=sum(e['response_source']=='parent_v2_model_cache' for e in experts),
                  control_differences=differences, expert_validated=False,
                  selection_counts=dict(single_choice_wires=single, multi_choice_wires=len(bundle['requests'])-single,
                                        model_abstained_wires=sum(v['prediction']=={'assessment':'unresolved'}
                                                                  for v in receipt['responses'].values())))
    atomic_json(output / 'report.json', report)
    print(json.dumps({'run_id': rid, 'cohorts': cohorts, 'control_differences': differences}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'evaluate'])
    parser.add_argument('--parent', type=Path, default=PARENT)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.parent.resolve(), args.output.resolve())
    else:
        evaluate(args.parent.resolve(), args.output.resolve())
