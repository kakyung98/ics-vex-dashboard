"""Audit the revised supplier review against its frozen v2 failures and archived controls."""
import argparse
from collections import Counter
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import zlib


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import supplier_evidence_review as contract
from src.item4.models.scenario_review_experts import digest as scope_sha
from src.item4.models.json_inference_client import parse_json
from tools.item4.verify_item4_moe_h200 import comparison
from tools.item4.item4_source_history import pinned_source


PARENT = 'moe-20261121T120040Z-d1c0719505bc'
PARENT_EXPORT = '2800bbee81b7bbe09aff1986dd7abe533adcc06f4efeae494e8e977abd63ae3e'
INDEPENDENT = '49ec049f44fdb9467e043e88e4c4f20def905d0cd183cc2734b0757bbf434c78'
SERIAL = '68e10ea0d79f4c26b5ca8c063c06c114e943568d07120dc076ff24f7fdce93b0'
CONTROL_EXPORTS = {
    'moe-20261121T112525Z-6d4b3c7e6c38': '0d997133b54f956ea39de625a7fe17795d3ec2adf7010ed7790899cc2afac747',
    'moe-20261121T112702Z-99e3a1e11d83': 'f5be83eb3e733e092f0be270fe68d6015d51589d4021e2b95369a221d84739bb',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sealed_bytes(path, expected):
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, f'Fingerprint differs for {path.name}')
    return raw


def cached_review(db, candidate, expert):
    stored = db.execute('SELECT value,response_sha FROM experts WHERE wire_sha=?', (expert['wire_sha256'],)).fetchone()
    require(stored and hashlib.sha256(stored[0]).hexdigest() == stored[1], 'Invalid cached v2 response fingerprint.')
    value = json.loads(stored[0])
    prediction = value['prediction']
    require(value['llm_used'] is True and prediction['finding'] == expert['verdict'] and
            expert['model'] == {k: value['model'][k] for k in ('provider', 'model')},
            'The archived non-supplier response differs from its scoped receipt.')
    cite = prediction['cite']
    if cite == 'none':
        expected = []
    else:
        product_ids = [eid for eid, _ in representatives(candidate['verified_product'])]
        name = expert['expert']
        if name == 'crosscheck' and cite in {f'e{i}' for i in range(1, len(product_ids) + 1)}:
            expected = [product_ids[int(cite[1:]) - 1]]
        else:
            observation = cite == 'e0' and name in {'inventory', 'crosscheck'}
            condition = (cite == 'e0' and name == 'conditions' or
                         cite == f'e{len(product_ids) + 1}' and name == 'crosscheck')
            require(observation or condition, 'V2 model returned an unknown evidence alias.')
            prefix = 'observation:' if observation else 'rule:'
            expected = [eid for eid in candidate['cited_evidence'] if eid.startswith(prefix)]
            require(len(expected) == 1, 'Ambiguous archived evidence binding.')
    require(expert['evidence_ids'] == expected, 'V2 model citation differs from this case.')


def selected_rows(parent_path):
    """Return case_id -> (failure|control, parent row SHA without newline, complete v2 row)."""
    parent = Path(parent_path).resolve()
    report = json.loads((parent / 'report.json').read_bytes())
    audit = json.loads(sealed_bytes(parent / 'independent_verification.json', INDEPENDENT))
    require(report['ledger']['run_id'] == audit['run_id'] == PARENT and
            report['candidates_sha256'] == audit['candidates_sha256'] == PARENT_EXPORT and
            report['ledger']['result']['candidates_sha256'] == PARENT_EXPORT,
            'The parent is not the verified full v2 run.')
    serial = json.loads(sealed_bytes(parent / 'independent_failed_expert_serial_replay.json', SERIAL))
    require(serial['official_run_id'] == PARENT and serial['official_attempts_added'] == 0 and
            serial['runtime_sha256'] == report['ledger']['code_hashes']['GPU runtime identity'] and
            serial['summary']['wire_classifications'] == {'same_evidence_rejection': 4},
            'The official serial failure comparison differs.')
    failures = {}
    for group in serial['results']:
        require(group['expert'] == 'supplier' and group['status'] == 'same_evidence_rejection',
                'Unexpected expert in the supplier failure cohort.')
        for case in group['official_rows']:
            require(case['id'] not in failures and case['reason'] == 'no_verified_conflict_pair',
                    'Unexpected or repeated failed supplier case.')
            failures[case['id']] = (case, group['wire_sha256'])
    controls = {}
    for run_id, pin in CONTROL_EXPORTS.items():
        archive = parent.parent / run_id
        require(json.loads((archive / 'report.json').read_bytes())['candidates_sha256'] == pin,
                'The archived control run differs.')
        for line in sealed_bytes(archive / 'candidates.jsonl', pin).splitlines():
            row = json.loads(line)
            require(row['run_id'] == run_id and row['id'] not in controls,
                    'Duplicate or foreign archived control.')
            controls[row['id']] = row
    require(len(failures) == 56 and len({case['cve'] for case, _ in failures.values()}) == 7 and
            len({wire for _, wire in failures.values()}) == 4 and len(controls) == 33 and
            not failures.keys() & controls.keys(), 'The disjoint 56 failures and 33 controls differ.')

    wanted = failures.keys() | controls.keys()
    selected = {}
    whole = hashlib.sha256()
    uri = (parent / 'records.sqlite3').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db, (parent / 'candidates.jsonl').open('rb') as handle:
        require({r[0] for r in db.execute("SELECT id FROM candidates WHERE generation != 'completed'")}
                == failures.keys(), 'The serial comparison omits current v2 failures.')
        for line in handle:
            whole.update(line)
            row = json.loads(line)
            identifier = row['id']
            if identifier not in wanted:
                continue
            stored = db.execute('SELECT row_sha,payload FROM candidates WHERE id=?', (identifier,)).fetchone()
            raw = line.rstrip(b'\r\n')
            fingerprint = hashlib.sha256(raw).hexdigest()
            require(stored and stored[0] == fingerprint and zlib.decompress(stored[1]) == raw and
                    row['run_id'] == PARENT and identifier not in selected,
                    'The selected exported row differs from its sealed checkpoint.')
            for expert in row['experts']:
                if expert['expert'] != 'supplier':
                    cached_review(db, row, expert)
            if identifier in failures:
                case, wire = failures[identifier]
                supplier = next(e for e in row['experts'] if e['expert'] == 'supplier')
                require((case['row_sha'], case['packet_sha'], case['scope_sha'], case['cve'], wire, case['reason']) ==
                        (fingerprint, row['packet_sha256'], supplier['input_sha256'], row['cve'],
                         supplier['wire_sha256'], supplier['reason_code']) and supplier['execution'] == 'error',
                        'A selected failure differs from its independent serial evidence.')
                cohort = 'failure'
            else:
                known = controls[identifier]
                require(row['packet_sha256'] == known['packet_sha256'] and
                        comparison([known], [row])['passed'],
                        'The original control and full v2 run disagree.')
                cohort = 'control'
            selected[identifier] = (cohort, fingerprint, row)
    require(whole.hexdigest() == PARENT_EXPORT and selected.keys() == wanted,
            'The full parent export or selected case membership differs.')
    return selected


def read_model_files(folder, parent):
    raw = (folder / 'requests.json').read_bytes()
    bundle = json.loads(raw)
    response_raw = (folder / 'responses.json').read_bytes()
    receipt = json.loads(response_raw)
    pins_raw = (folder / 'parent_runtime_pins.json').read_bytes()
    pins = json.loads(pins_raw)
    report_raw = (parent / 'report.json').read_bytes()
    report = json.loads(report_raw)
    require(bundle['parent_run_id'] == receipt['parent_run_id'] == pins['parent_run_id'] == PARENT and
            bundle['contract_version'] == receipt['contract_version'] == contract.VERSION and
            receipt['inference_role'] == 'operating-record-review' and
            receipt['inference_method'] == 'frozen_v2_serial_constrained_greedy' and
            pins['model_identity'] == receipt['model_identity'] == report['backend_identity'] and
            pins['parent_candidates_sha256'] == receipt['parent_candidates_sha256'] == PARENT_EXPORT and
            pins['parent_report_sha256'] == receipt['parent_report_sha256'] == hashlib.sha256(report_raw).hexdigest() and
            receipt['requests_sha256'] == hashlib.sha256(raw).hexdigest() and
            receipt['pins_sha256'] == hashlib.sha256(pins_raw).hexdigest(),
            'Supplier request, response, weight or parent fingerprints differ.')
    require(receipt['worker_sha256'] == hashlib.sha256(
        (ROOT / 'tools/item4/run_item4_supplier_review_worker.py').read_bytes()).hexdigest() and
            receipt['serial_dependency_sha256'] == pins['serial_dependency_sha256'] and
            all(report['ledger']['code_hashes'].get(Path(k).name) == v
                for k, v in receipt['serial_dependency_sha256'].items()),
            'The serial generation code differs from its receipt.')
    requests = {}
    for entry in bundle['requests']:
        wire = entry['wire_sha256']
        request = {k: entry[k] for k in ('system', 'packet')}
        require(set(entry) == {'wire_sha256', 'system', 'packet'} and wire == contract.wire_sha256(request)
                and wire not in requests, 'Invalid or duplicate serialized supplier request.')
        requests[wire] = request
    outputs = receipt['responses']
    require(requests.keys() == outputs.keys() and receipt['actual_model_calls'] == len(requests),
            'Incomplete model receipt coverage.')
    for output in outputs.values():
        model = output['model']
        generation = output['generation']
        require(output['llm_used'] is True and model['provider'] == 'local_shared_base' and
                model['model'] == receipt['model_identity']['model'] and model['adapter'] is None and
                parse_json(output['raw']) == output['prediction'] and generation['constrained_json'] is True
                and all(type(generation[k]) is int and generation[k] > 0 for k in ('input_tokens', 'output_tokens')),
                'Missing original model output or invalid token-generation receipt.')
    return requests, outputs, receipt['requests_sha256'], hashlib.sha256(response_raw).hexdigest()


def representatives(product):
    kept = {}
    for evidence in product['evidence']:
        key = (evidence['version_membership'], evidence['status'])
        if key not in kept:
            row = {k: evidence[k] for k in ('product_key', 'source_version', 'status', 'version_membership')}
            kept[key] = (evidence['evidence_id'], row)
    return list(kept.values())


def check_supplier(old, new, rows, request, output):
    """Independently resolve the recorded model choice using this case's source-row order."""
    require(request == contract.build_request(rows) and new['wire_sha256'] == contract.wire_sha256(request) and
            new['v2_wire_sha256'] == old['wire_sha256'] and new['v2_scope_sha256'] == old['input_sha256'],
            'The revised model request differs from the parent supplier rows or their order.')
    require(new['contract_version'] == contract.VERSION and
            new['input_sha256'] == scope_sha([contract.VERSION, new['wire_sha256'], [eid for eid, _ in rows]]) and
            new['response_source'] == 'pilot_supplier_model' and new['llm_used'] is True and
            new['execution'] in {'model', 'cached'} and new['model_called'] is (new['execution'] == 'model'),
            'Incorrect source or execution mode for the revised supplier.')
    require(new['model'] == {k: output['model'][k] for k in ('model', 'provider')},
            'Supplier receipt model differs from genuine model output.')
    prediction = output['prediction']
    options = request['packet']['schema']['properties']['assessment']['enum']
    require(isinstance(prediction, dict) and set(prediction) == {'assessment'}
            and prediction['assessment'] in options, 'Model response exceeds the verified choices.')
    choice = prediction['assessment']
    require(new['selection'] == choice, 'Stored supplier choice differs from the model output.')
    eligible = {}
    for i, (eid, row) in enumerate(rows):
        if row['version_membership'] == 'true':
            eligible.setdefault(row['status'], (f'e{i}', eid))
    if choice == 'unresolved':
        verdict, citations = 'unresolved', []
    elif choice == 'conflicting_group0':
        members = sorted(eligible.values())
        require(len(members) >= 2 and [alias for alias, _ in members] == request['packet']['citation_groups']['group0'],
                'Supply at least two different, applicable source statuses for a conflict.')
        verdict, citations = 'conflicting', [eid for _, eid in members]
    else:
        matches = [(status, eid) for status, (alias, eid) in eligible.items() if choice == 'support_' + alias]
        require(len(eligible) == 1 and len(matches) == 1, 'The selected row does not apply to the scoped version.')
        verdict, eid = matches[0]
        citations = [eid]
    require(new['verdict'] == verdict and new['evidence_ids'] == citations,
            'Supplier conclusion or source citations differ from the actual constrained model choice.')


def check_case(old, new, cohort, sha, requests, outputs):
    for key in ('id', 'cve', 'synthetic', 'expert_validated', 'label_kind', 'packet_sha256', 'verified_product',
                'product_reasons', 'source_rule_identities', 'routed_experts', 'inference_role'):
        require(new[key] == old[key], f'Frozen case field changed: {key}')
    require(new['version'] == 'item4-scenario-moe/2+supplier-review/1' and new['parent_run_id'] == PARENT and
            new['run_id'] != PARENT and new['parent_row_sha256'] == sha and new['cohort'] == cohort and
            new['generation_status'] == 'completed' and new['expert_validated'] is False and new['synthetic'] is True,
            'Candidate scope, generation or provenance differs.')
    require([e['expert'] for e in new['experts']] == new['routed_experts'], 'Expert routing differs.')
    rows = representatives(old['verified_product'])
    lookup = {e['expert']: e for e in old['experts']}
    bindings = set()
    source_evidence = dict(old['cited_evidence'])
    for item in old['verified_product']['evidence']:
        fields = ('product_key', 'status', 'version_membership', 'source_version', 'source_file', 'document_sha256',
                  'product_pointer', 'status_pointer')
        source_evidence[item['evidence_id']] = {k: item[k] for k in fields if k in item}
    for expert in new['experts']:
        name = expert['expert']
        prior = lookup[name]
        if name == 'supplier':
            wire = expert['wire_sha256']
            require(wire in requests, 'Supplier request is absent from the model run.')
            check_supplier(prior, expert, rows, requests[wire], outputs[wire])
            supplier = expert
        else:
            require(expert['execution'] == 'cached' and expert['model_called'] is False and expert['llm_used'] is True
                    and expert['response_source'] == 'parent_v2_model_cache'
                    and all(expert.get(k) == prior.get(k) for k in ('wire_sha256', 'input_sha256', 'verdict',
                            'evidence_ids', 'reason_code', 'error_kind', 'model')),
                    'The supposedly identical v2 expert computation or its scoped citations changed.')
        bindings.update(expert['evidence_ids'])
    require(new['v2_input_sha256'] == old['input_sha256'] and new['input_sha256'] ==
            scope_sha([new['version'], old['input_sha256'], supplier['wire_sha256']]),
            'The pilot scenario is not bound to the original scenario and the revised supplier input.')
    require(new['evidence_ids'] == sorted(bindings) and new['cited_evidence'] ==
            {eid: source_evidence[eid] for eid in bindings}, 'Candidate evidence differs from its cited source rows.')

    # In this closed sample each unknown/contradictory supplier scope is unchanged. Its only possible
    # non-held outcome uses complete inventory absence. The positive controls exercised the same v2 gates.
    require(new['candidate_status'] == old['candidate_status'], 'A candidate status changed within the fixed pilot.')
    if old['verified_product']['state'] in {'unknown', 'conflicting'}:
        require(new['candidate_status'] in {'under_investigation', 'not_affected'},
                'A supplier claim promoted an uncertain product to affected or fixed.')
        require(new['reasons'] == old['reasons'], 'Downstream hold reasons changed for a frozen uncertain scope.')
    if new['candidate_status'] == 'not_affected':
        require(lookup['inventory']['verdict'] == 'absent_complete' and
                lookup['crosscheck']['verdict'] == 'corroborated', 'The sample absence decision lacks its independent checks.')
    return supplier


def verify(parent_path, pilot_path):
    parent = Path(parent_path).resolve()
    path = Path(pilot_path).resolve()
    selected = selected_rows(parent)
    requests, outputs, request_sha, response_sha = read_model_files(path.parent, parent)
    statuses = {cohort: Counter() for cohort in ('failure', 'control')}
    supplier_findings = {cohort: Counter() for cohort in statuses}
    counts = Counter()
    seen = set()
    run_ids = set()
    calls = Counter()
    controls = Counter()
    holds = {name: Counter() for name in statuses}
    product_holds = {name: Counter() for name in statuses}
    wires = set()
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for line in source:
            digest.update(line)
            row = json.loads(line)
            identifier = row['id']
            require(identifier in selected and identifier not in seen, 'Extra or duplicate pilot case.')
            seen.add(identifier)
            cohort, sha, old = selected[identifier]
            supplier = check_case(old, row, cohort, sha, requests, outputs)
            run_ids.add(row['run_id'])
            statuses[cohort][row['candidate_status']] += 1
            supplier_findings[cohort][supplier['verdict']] += 1
            wire = supplier['wire_sha256']
            wires.add(wire)
            if supplier['model_called']:
                calls[wire] += 1
            counts.update(e['response_source'] for e in row['experts'])
            if row['candidate_status'] == 'under_investigation':
                holds[cohort].update(set(row['reasons']))
                if 'supplier_evidence_conflicting_or_unresolved' in row['reasons']:
                    product_holds[cohort].update(set(row['product_reasons']))
            if cohort == 'control':
                for field in ('candidate_status', 'reasons', 'product_reasons', 'evidence_ids'):
                    controls[field] += (row[field] != old[field])
                prior = next(e for e in old['experts'] if e['expert'] == 'supplier')
                controls['supplier_verdict'] += supplier['verdict'] != prior['verdict']
                controls['supplier_citations'] += supplier['evidence_ids'] != prior['evidence_ids']
    require(seen == selected.keys() and len(run_ids) == 1 and wires == set(requests) and
            calls == Counter({wire: 1 for wire in requests}), 'Pilot cases, version or fresh call/reuse counts differ.')
    run_id = run_ids.pop()
    report = json.loads((path.parent / 'report.json').read_bytes())
    code = {p.name: hashlib.sha256(pinned_source(p, report['code_hashes'].get(p.name)).read_bytes()).hexdigest() for p in (
        ROOT / 'tools/item4/run_item4_supplier_pilot.py', ROOT / 'src/item4/evaluation/supplier_evidence_review.py',
        ROOT / 'tools/item4/run_item4_supplier_review_worker.py')}
    require(report['run_id'] == run_id == 'moe-supplier-pilot-' + scope_sha([
                'item4-scenario-moe/2+supplier-review/1', PARENT, request_sha, response_sha, code])[:16]
            and report['parent_run_id'] == PARENT and report['code_hashes'] == code
            and report['candidates_sha256'] == digest.hexdigest() and report['requests_sha256'] == request_sha
            and report['responses_sha256'] == response_sha and report['actual_model_calls'] == len(wires)
            and report['parent_expert_receipts_reused'] == counts['parent_v2_model_cache']
            and report['expert_validated'] is False,
            'The published pilot report differs from the reviewed build, raw inputs or outputs.')
    for name, distribution in statuses.items():
        section = report['cohorts'][name]
        require(section['candidate_statuses'] == distribution and section['hold_reasons'] == holds[name] and
                section['product_hold_reasons'] == product_holds[name] and
                section['generation_statuses'] == {'completed': sum(distribution.values())} and
                section['generation_failure_reasons'] == {},
                'The published cohort counts differ from the individual pilot cases.')
    reported_differences = dict(report['control_differences'])
    reported_differences['supplier_citations'] = reported_differences.pop('supplier_evidence_ids')
    require(reported_differences == controls, 'Published control differences do not match the frozen controls.')
    return dict(run_id=run_id, parent_run_id=PARENT, parent_candidates_sha256=PARENT_EXPORT,
                candidates_sha256=digest.hexdigest(), requests_sha256=request_sha, responses_sha256=response_sha,
                unique_scenarios=len(seen), unique_cves=len({old['cve'] for _, _, old in selected.values()}),
                cohorts={name: sum(states.values()) for name, states in statuses.items()}, candidate_statuses=statuses,
                supplier_findings=supplier_findings, control_mismatches=controls, actual_supplier_model_calls=sum(calls.values()),
                cached_supplier_receipts=counts['pilot_supplier_model'] - sum(calls.values()),
                reused_non_supplier_receipts=counts['parent_v2_model_cache'],
                single_choice_wires=sum(len(r['packet']['schema']['properties']['assessment']['enum']) == 1
                                        for r in requests.values()), independent_expert_reviews=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('parent', type=Path)
    parser.add_argument('pilot_candidates', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    audit = verify(args.parent, args.pilot_candidates)
    result = json.dumps(audit, indent=2, ensure_ascii=False)
    if args.output:
        with args.output.open('x', encoding='utf-8') as f:
            f.write(result + '\n')
    print(result)
