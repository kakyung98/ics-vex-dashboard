"""Independently replay unique supplier conflict rejections from a read-only v2 checkpoint."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.models import scenario_review_experts as moe; from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation.bulk_scenario_runner import atomic_json; from src.item4.evaluation.bulk_scenario_runner import checked_bytes
from src.item4.models.remote_gpu_expert_client import H200Batch


REASON = 'no_verified_conflict_pair'
FIRST_FILE = 'independent_supplier_serial_replay_17664.json'
FIRST_SHA = 'f60c3f301678854b7e7ac1c032655b1fb5602a944132edfc208d178ab4aa56b5'


from src.common.paths import source_path

def runtime_sha(identity):
    return runs.sha(json.dumps(identity, sort_keys=True).encode())


def snapshot(directory):
    groups = defaultdict(list)
    uri = (directory / 'records.sqlite3').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute('BEGIN')
        [(run_id, metadata)] = db.execute('SELECT run_id,pins FROM metadata').fetchall()
        pins = json.loads(metadata)
        if run_id != directory.name or pins['run_id'] != run_id or pins['generation_method'] != 'scenario_moe_h200_llm':
            raise ValueError('Expected the declared v2 H200 population checkpoint')
        n = db.execute('SELECT count(*) FROM candidates').fetchone()[0]
        query = """SELECT id,cve,packet_sha,row_sha,payload FROM candidates WHERE generation!='completed' ORDER BY ordinal"""
        for case_id, cve, packet_sha, row_sha, payload in db.execute(query):
            row = json.loads(checked_bytes(payload, row_sha))
            if (row['run_id'], row['id'], row['cve'], row['packet_sha256']) != (run_id, case_id, cve, packet_sha):
                raise ValueError('Candidate checkpoint identity mismatch')
            failed = [e for e in row['experts'] if e['execution'] == 'error']
            if not failed:
                raise ValueError('Incomplete candidate has no failed expert receipt')
            for e in failed:
                groups[e['expert'], e['wire_sha256']].append(dict(id=case_id, cve=cve, row_sha=row_sha,
                    packet_sha=packet_sha, scope_sha=e['input_sha256'], reason=e['reason_code']))
    return pins, n, groups


def reconstruct(cve, folder, manifest):
    packet = runs.input_packet(folder, manifest, cve)
    product, _ = runs.scoped_inputs(packet)
    representatives = {}
    for eid, row in moe._product_rows(product):
        representatives.setdefault((row['version_membership'], row['status']), (eid, row))
    rows = list(representatives.values())
    requests = []
    def capture(system, packet, *, role):
        requests.append(dict(system=system, packet=packet))
        return {}
    receipt = moe._expert('supplier', rows, capture, None)
    [request] = requests
    return rows, request, receipt, {case['id'] for case in packet['cases']}


def prior_result(directory, pins, wire, members):
    path = directory / FIRST_FILE
    if not path.is_file() or runs.file_sha(path) != FIRST_SHA:
        return None
    prior = runs.sealed_json(path, FIRST_SHA)
    if (prior['official_run_id'] != pins['run_id']
            or runtime_sha(prior['model_runtime']) != pins['code_hashes']['GPU runtime identity']
            or any(pins['code_hashes'].get(k) != v for k, v in prior['source_hashes'].items())):
        return None
    for old in prior['results']:
        if old['wire_sha256'] != wire:
            continue
        old_rows = {(r['id'], r['row_sha256']) for r in old['official_rows']}
        if any((r['id'], r['row_sha']) in old_rows and r['packet_sha'] == old['packet_sha256']
               and r['scope_sha'] == old['scope_input_sha256'] for r in members):
            return old['independent_serial_model_output']
    return None


def single(client, request):
    runtime = client.identity['runtime_sha256']
    response = client.session.post(client.url + '/serial', json=dict(runtime_sha256=runtime, requests=[request]),
                                   timeout=(10, 300))
    response.raise_for_status()
    result = response.json()
    if result['runtime_sha256'] != runtime or len(result['outputs']) != 1:
        raise ValueError('Incomplete or differently pinned serial response')
    return result['outputs'][0]


def inspect(run_id, port, inspect_only):
    if not re.fullmatch(r'moe-\d{8}T\d{6}Z-[a-f0-9]{12}', run_id):
        raise ValueError('Invalid run ID')
    directory = runs.OUTPUT / run_id
    pins, n, groups = snapshot(directory)
    if not inspect_only and n != pins['total']:
        raise ValueError('The first pass does not yet cover the target population. Use --inspect-only for a snapshot.')
    from tools.item4.item4_source_history import pinned_source
    for name in ('item4_scenario_moe.py', 'item4_scenario_run.py', 'item4_advisory_context.py'):
        pinned_source(source_path(name, root=ROOT), pins['code_hashes'][name])
    base = json.loads(runs.BASELINE.read_bytes())
    folder = Path(base['artifact_directory'])
    manifest = runs.sealed_json(folder / 'delivery_manifest.json', pins['data_hashes']['v3 delivery manifest'])
    records = {}
    results = []
    calls = 0
    client = None
    for (expert, wire), members in sorted(groups.items()):
        result = dict(expert=expert, wire_sha256=wire, scenario_count=len(members), official_rows=members,
                      official_reason_counts=dict(Counter(m['reason'] for m in members)), status='unverified')
        results.append(result)
        if expert != 'supplier' or set(result['official_reason_counts']) != {REASON}:
            result['detail'] = 'unsupported_expert_or_reason'
            continue
        scopes = {}
        for member in members:
            cve = member['cve']
            if cve not in records:
                records[cve] = reconstruct(cve, folder, manifest)
            rows, request, receipt, ids = records[cve]
            if (manifest[f'{runs.PREFIX}/cves/{cve}.json'] != member['packet_sha'] or member['id'] not in ids
                    or wire != receipt['wire_sha256'] or member['scope_sha'] != receipt['input_sha256']):
                raise ValueError('Frozen packet, scenario, supplier wire or scoped citation fingerprint differs')
            scopes[member['scope_sha']] = rows
        output = prior_result(directory, pins, wire, members)
        if output:
            result.update(source=FIRST_FILE, source_sha256=FIRST_SHA)
        elif inspect_only:
            result['detail'] = 'exact_request_verified_serial_replay_pending'
            continue
        else:
            from requests import RequestException
            try:
                if client is None:
                    client = H200Batch(port)
                    if runtime_sha(client.identity) != pins['code_hashes']['GPU runtime identity']:
                        raise ValueError('The H200 identity differs from the original run')
                calls += 1
                output = single(client, request)
            except RequestException as exc:
                result.update(detail='serial_transport_error', error=type(exc).__name__)
                continue
            result['source'] = 'independent_h200_serial'
        if not isinstance(output, dict) or output.get('llm_used') is not True or not output.get('model'):
            result['detail'] = 'missing_serial_generation_receipt'
            continue
        checks = {}
        for scope_sha, rows in scopes.items():
            checked = moe._expert('supplier', rows, lambda *a, **kw: output, None)
            checks[scope_sha] = {k: checked.get(k) for k in ('reason_code', 'verdict', 'evidence_ids', 'error_kind')}
        result.update(serial_output=output, scoped_checks=checks)
        if all(c['reason_code'] == REASON for c in checks.values()):
            result['status'] = 'same_evidence_rejection'
        elif all(c['error_kind'] is None for c in checks.values()):
            result['status'] = 'serial_expert_output_accepted'
        else:
            result['status'] = 'different_or_mixed_rejection'
    classifications = Counter(r['status'] for r in results)
    stats = dict(snapshot_cases=n, target_cases=pins['total'], affected_scenarios=len(
        {m['id'] for members in groups.values() for m in members}), distinct_failed_wires=len(groups),
        independent_serial_requests=calls, wire_classifications=dict(classifications))
    if not inspect_only:
        report = dict(kind='independent_failed_expert_serial_replay', official_run_id=run_id,
                      created_at=datetime.now(timezone.utc).isoformat(), runtime_sha256=pins['code_hashes']['GPU runtime identity'],
                      official_attempts_added=0, summary=stats, results=results)
        atomic_json(directory / 'independent_failed_expert_serial_replay.json', report)
    print(json.dumps(dict(stats, wires=[{k: r[k] for k in ('expert', 'wire_sha256', 'scenario_count', 'status')}
                                        for r in results]), ensure_ascii=False, indent=2))
    return stats


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--port', type=int, default=18128)
    parser.add_argument('--inspect-only', action='store_true', help='Check snapshot pins and reuse eligibility without inference or writes.')
    args = parser.parse_args()
    inspect(args.run_id, args.port, args.inspect_only)
