"""Independently recount an Item 4 run against the sealed frozen scenario index."""
import argparse
from collections import Counter
from contextlib import closing
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import re
import sqlite3
import sys
from urllib.request import urlopen
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import scenario_evaluation_runner as runs

COUNTS = ('generation_statuses', 'candidate_statuses', 'hold_reasons',
          'product_hold_reasons', 'generation_failure_reasons')


def source_cases(delivery, report, selected, expect_full):
    """The delivery's aggregate inputs JSONL is pinned independently of its per-CVE packets."""
    delivery = Path(delivery or json.loads(runs.BASELINE.read_bytes())['artifact_directory'])
    pins = report['data_hashes']
    manifest = runs.sealed_json(delivery / 'delivery_manifest.json', pins['v3 delivery manifest'])
    population_name = runs.PREFIX + '/population_ledger.json'
    population = runs.sealed_json(delivery / population_name, manifest[population_name])['cves']
    if pins['frozen CVE population'] != manifest[population_name]:
        raise ValueError('The run and delivery disagree on the frozen population hash.')
    chosen = set(selected) if selected is not None else set(population)
    if (len(population) != len(set(population)) or not chosen.issubset(population) or
            (selected is not None and len(chosen) != len(selected))):
        raise ValueError('Invalid selected population.')
    if expect_full and (len(chosen) != 12418 or chosen != set(population) or report['total'] != 97553):
        raise ValueError('Expected the complete 12,418-CVE, 97,553-scenario population.')
    name = runs.PREFIX + '/inputs.jsonl'
    expected = {}
    digest = hashlib.sha256()
    with (delivery / name).open('rb') as stream:
        for raw in stream:
            digest.update(raw)
            case = json.loads(raw)
            if case['cve'] in chosen:
                if case['id'] in expected or not case['synthetic']:
                    raise ValueError('Duplicate or non-synthetic frozen scenario.')
                expected[case['id']] = (case['cve'], case['context']['deployment'])
    if (digest.hexdigest() != manifest[name] or len(expected) != report['total'] or
            {cve for cve, _ in expected.values()} != chosen):
        raise ValueError('Scenario index or membership differs from the pinned run.')
    selected_packets = {cve: manifest[f'{runs.PREFIX}/cves/{cve}.json'] for cve in chosen}
    packet_set_sha = hashlib.sha256(json.dumps(selected_packets, sort_keys=True).encode()).hexdigest()
    if packet_set_sha != pins['selected input packets']:
        raise ValueError('The run and delivery disagree on the selected source packets.')
    if 'selected case IDs' in pins or expect_full:
        ids_sha = hashlib.sha256(json.dumps(sorted(expected), separators=(',', ':')).encode()).hexdigest()
        if pins.get('selected case IDs') != ids_sha:
            raise ValueError('The run and delivery disagree on the selected scenario IDs.')
    return expected, manifest


def audit_rows(rows, expected, manifest, run_id):
    """Reconstruct counts from individual traces, without calling the runner's aggregation code."""
    statuses, generations, roles, executions, deployments = (Counter() for _ in range(5))
    holds, product_holds, failures = Counter(), Counter(), Counter()
    states = {}
    conflicts = set()
    seen = set()
    for row in rows:
        identifier = row['id']
        if identifier in seen or identifier not in expected:
            raise ValueError('Unexpected or duplicated candidate ID: ' + identifier)
        seen.add(identifier)
        cve, deployment = expected[identifier]
        if (row['cve'] != cve or row['run_id'] != run_id or row['expert_validated'] is not False or
                row['synthetic'] is not True or row['packet_sha256'] != manifest[f'{runs.PREFIX}/cves/{cve}.json']):
            raise ValueError('Candidate and frozen scenario do not match.')
        product = row['verified_product']
        if product['state'] != states.setdefault(cve, product['state']):
            raise ValueError('Different product evidence states for scenarios from the same input packet.')
        generation = row['generation_status']
        generations[generation] += 1
        errors = set()
        experts = row['experts']
        routed = [e['expert'] for e in experts]
        if (len(set(routed)) != len(routed) or not {'inventory', 'crosscheck'}.issubset(routed)
                or set(routed) - {'supplier','inventory','conditions','crosscheck'} or row['routed_experts'] != routed):
            raise ValueError('Incomplete or unexpected expert routing.')
        n_errors = sum(e['execution'] == 'error' for e in experts)
        observed = 'failed' if n_errors == len(experts) else 'partial' if n_errors else 'completed'
        if generation != observed:
            raise ValueError('Scenario generation status differs from the expert traces.')
        for expert in experts:
            mode = expert['execution']
            executions[mode] += 1
            roles[expert['expert']] += 1
            if mode == 'error':
                errors.add(expert.get('reason_code') or expert.get('error') or 'reason_not_recorded')
            elif (not expert['llm_used'] or mode not in {'model', 'cached'} or
                    (mode == 'model') != expert['model_called']):
                raise ValueError('Expected a model result or its cached model response.')
            if expert['expert'] == 'supplier' and expert['verdict'] == 'conflicting':
                cited = {r['status'] for r in product['evidence'] if r['version_membership'] == 'true'
                         and r['evidence_id'] in expert['evidence_ids']}
                if len(cited) < 2:
                    raise ValueError('A supplier conflict requires distinct in-scope source statuses.')
                conflicts.add(cve)
        if generation in {'partial', 'failed'}:
            failures.update(errors or {'reason_not_recorded'})
            continue
        if generation != 'completed' or errors:
            raise ValueError('Inconsistent scenario generation outcome.')
        status = row['candidate_status']
        if status not in {'affected', 'fixed', 'not_affected', 'under_investigation'}:
            raise ValueError('Unknown candidate status.')
        statuses[status] += 1
        if status == 'not_affected':
            deployments[deployment] += 1
        if status == 'under_investigation':
            reasons = set(row.get('reasons') or ['reason_not_recorded'])
            holds.update(reasons)
            if 'supplier_evidence_conflicting_or_unresolved' in reasons:
                product_holds.update(set(row.get('product_reasons', [])))
    summary = dict(generation_statuses=generations, candidate_statuses=statuses, hold_reasons=holds,
                   product_hold_reasons=product_holds, generation_failure_reasons=failures)
    return dict(run_id=run_id, unique_scenarios=len(seen), expected_scenarios=len(expected), unique_cves=len(states),
                duplicate_ids=0, missing_scenarios=len(expected)-len(seen), states=states,
                not_affected_by_deployment=deployments, supplier_conflicts_cited=sorted(conflicts),
                expert_roles=roles, expert_executions=executions, independently_reviewed=0, **summary)


def get_json(url):
    with urlopen(url, timeout=30) as response:
        return json.load(response)


def v1_rejections(population, manifest_sha):
    receipt = json.loads((runs.REPLAY / 'independent_verification.json').read_bytes())
    report = runs.sealed_json(runs.REPLAY / 'report.json', receipt['verified_report_sha256'])
    audit_sha = report['ledgers']['cve_audit.jsonl']
    raw = (runs.REPLAY / 'cve_audit.jsonl').read_bytes()
    if report['source_manifest_sha256'] != manifest_sha or hashlib.sha256(raw).hexdigest() != audit_sha:
        raise ValueError('The historical V1 cohort or its delivery differs from its sealed report.')
    seen, rejected = set(), set()
    for row in map(json.loads, raw.splitlines()):
        cve = row['cve']
        if cve in seen or type(row['prior_v1']) is not bool:
            raise ValueError('Duplicated or ambiguous V1 cohort membership.')
        seen.add(cve)
        if row['prior_v1']:
            rejected.add(cve)
    if seen != population or len(rejected) != 3640:
        raise ValueError('The V1 selection does not match the original population.')
    return rejected, audit_sha


def cohort_rows(stream, run_id, expected, rejected, expected_sha):
    """Hash the complete final JSONL and yield only the historical member rows."""
    whole_sha = hashlib.sha256()
    seen = set()
    for raw in stream:
        whole_sha.update(raw)
        row = json.loads(raw)
        identifier = row['id']
        if (identifier in seen or identifier not in expected or row['cve'] != expected[identifier][0]
                or row['run_id'] != run_id):
            raise ValueError('The full export has a duplicate or unexpected scenario identity.')
        seen.add(identifier)
        if row['cve'] in rejected:
            yield row
    if len(seen) != len(expected) or whole_sha.hexdigest() != expected_sha:
        raise ValueError('The full export has missing scenarios or differs from the sealed result.')


def verify_v1(run_id, port=8114, delivery=None):
    if not re.fullmatch(r'moe-[A-Za-z0-9-]+', run_id):
        raise ValueError('Expected a scenario evaluation run ID.')
    folder = runs.OUTPUT / run_id
    local = json.loads((folder / 'report.json').read_bytes())
    report = local['ledger']
    if report['status'] not in {'completed', 'partial', 'failed'} or report['completed'] != report['total']:
        raise ValueError('A final exported attempt for every scenario is required for the V1 cohort audit.')
    live = get_json(f'http://127.0.0.1:{port}/api/item4/evaluation-runs/{run_id}/report')
    if (live != report or report['result']['candidates_sha256'] != local['candidates_sha256']
            or report['run_id'] != run_id):
        raise ValueError('The recorded report and served run do not seal the same candidate export.')
    expected, manifest = source_cases(delivery, report, local['selected_cves'], True)
    population = {cve for cve, _ in expected.values()}
    manifest_sha = report['data_hashes']['v3 delivery manifest']
    rejected, audit_sha = v1_rejections(population, manifest_sha)
    selection = {identifier: v for identifier, v in expected.items() if v[0] in rejected}
    with (folder/'candidates.jsonl').open('rb') as stream:
        rows = cohort_rows(stream, run_id, expected, rejected, local['candidates_sha256'])
        result = audit_rows(rows, selection, manifest, run_id)
    if result['missing_scenarios'] or result['unique_cves'] != len(rejected):
        raise ValueError('At least one original V1 rejection or its scenarios is missing.')
    statuses = {key: result['candidate_statuses'][key]
                for key in ('affected','fixed','not_affected','under_investigation')}
    generations = {key: result['generation_statuses'][key] for key in ('completed','partial','failed')}
    return dict(run_id=run_id, mode='original_v1_rejections', selection_field='prior_v1',
                selection_ledger_sha256=audit_sha, source_manifest_sha256=manifest_sha,
                candidates_sha256=local['candidates_sha256'], full_population_cves=len(population),
                full_scenarios=len(expected), expected_cves=len(rejected), unique_cves=result['unique_cves'],
                expected_scenarios=len(selection), unique_scenarios=result['unique_scenarios'],
                missing_cves=0, missing_scenarios=0, duplicate_ids=0, candidate_count=sum(statuses.values()),
                incomplete_generation_count=generations['partial'] + generations['failed'],
                candidate_statuses=statuses, generation_statuses=generations, hold_reasons=result['hold_reasons'],
                product_hold_reasons=result['product_hold_reasons'],
                generation_failure_reasons=result['generation_failure_reasons'], independently_reviewed=0,
                label_kind='synthetic_scenario_candidate')


def verify_metadata(db, record):
    db.execute('BEGIN')
    pins = {k: record[k] for k in ('run_id', 'generation_method', 'code_hashes', 'data_hashes', 'model_hashes', 'total')}
    records = db.execute('SELECT run_id,pins FROM metadata').fetchall()
    if len(records) != 1 or records[0][0] != record['run_id'] or json.loads(records[0][1]) != pins:
        raise ValueError('Checkpoint metadata differs from the original run.')


def checkpoint_rows(path, record, expected):
    """Hold one SQLite read snapshot while the worker continues writing its WAL."""
    order = sorted(expected, key=lambda identifier: expected[identifier][0])
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=20)) as db:
        verify_metadata(db, record)
        for ordinal, identifier, cve, packet, generation, sha, blob in db.execute(
                'SELECT ordinal,id,cve,packet_sha,generation,row_sha,payload FROM candidates ORDER BY ordinal'):
            raw = zlib.decompress(blob)
            if (not 0 <= ordinal < len(order) or order[ordinal] != identifier
                    or hashlib.sha256(raw).hexdigest() != sha):
                raise ValueError('Invalid checkpoint row fingerprint or ordinal.')
            row = json.loads(raw)
            if (row['id'], row['cve'], row['packet_sha256'], row['generation_status']) != (identifier, cve, packet, generation):
                raise ValueError('Checkpoint row differs from its stored identity.')
            yield row


def retry_history(db, run_id):
    """Check all replaced attempts and the final stored payload of every retried scenario."""
    def checked(identifier, row_sha, payload):
        raw = zlib.decompress(payload)
        if hashlib.sha256(raw).hexdigest() != row_sha:
            raise ValueError('Retry-history payload fingerprint mismatch.')
        row = json.loads(raw)
        if row['id'] != identifier or row['run_id'] != run_id:
            raise ValueError('Retry-history scenario or run identity changed.')
        frozen = (row['cve'], row['packet_sha256'], row['input_sha256'], row['version'])
        return row, frozen

    prior = {}
    for identifier, attempt, row_sha, blob in db.execute(
            'SELECT id,attempt,row_sha,payload FROM prior_attempts ORDER BY id,attempt'):
        row, frozen = checked(identifier, row_sha, blob)
        count, original = prior.get(identifier, (0, frozen))
        if (type(attempt) is not int or attempt != count + 1 or frozen != original
                or row['generation_status'] not in {'partial', 'failed'}):
            raise ValueError('Invalid superseded attempt order, input or generation outcome.')
        prior[identifier] = (attempt, frozen)

    superseded = sum(count for count, _ in prior.values())
    generations, statuses = Counter(), Counter()
    for identifier, cve, packet, generation, attempt, row_sha, blob in db.execute(
            'SELECT id,cve,packet_sha,generation,attempts,row_sha,payload FROM candidates WHERE attempts IS NOT 1'):
        row, frozen = checked(identifier, row_sha, blob)
        count, original = prior.pop(identifier, (0, None))
        if (type(attempt) is not int or attempt != count + 1 or frozen != original
                or (cve, packet, generation) != (row['cve'], row['packet_sha256'], row['generation_status'])
                or generation not in {'completed', 'partial', 'failed'}):
            raise ValueError('Final retry does not match its previous attempts or committed identity.')
        generations[generation] += 1
        if generation == 'completed':
            status = row['candidate_status']
            if status not in {'affected', 'fixed', 'not_affected', 'under_investigation'}:
                raise ValueError('Invalid final retried candidate status.')
            statuses[status] += 1
    if prior:
        raise ValueError('Superseded attempts are missing their final retried scenario.')
    return dict(unique_retried_scenarios=sum(generations.values()), superseded_attempts=superseded,
                recovered_to_completed=generations['completed'], still_partial=generations['partial'],
                still_failed=generations['failed'], candidate_statuses=dict(statuses))


def exported_rows(directory, record, selected, expected, cache_count, retry_counts=None):
    """Match every exported row to the committed scenario and the expert responses used by its routes."""
    rank = {cve: i for i, cve in enumerate(selected)}
    order = sorted(expected, key=lambda identifier: rank[expected[identifier][0]])
    uri = (directory / 'records.sqlite3').resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, timeout=20)) as db, (directory/'candidates.jsonl').open('rb') as stream:
        verify_metadata(db, record)
        if retry_counts is not None:
            retry_counts.update(retry_history(db, record['run_id']))
        valid_responses = set()
        for wire_sha, raw in db.execute('SELECT wire_sha,value FROM experts'):
            response = json.loads(raw)
            if response.get('llm_used') is not True or not response.get('model') or not isinstance(response.get('prediction'), dict):
                raise ValueError('Run cache lacks a model response for its recorded request.')
            valid_responses.add(wire_sha)
        if len(valid_responses) != cache_count:
            raise ValueError('Stored model response count differs from the artifact report.')
        records = db.execute('SELECT ordinal,id,row_sha FROM candidates ORDER BY ordinal')
        for line, saved in zip_longest(stream, records):
            if line is None or saved is None or not line.endswith(b'\n'):
                raise ValueError('The exported rows and committed checkpoint have different boundaries.')
            ordinal, identifier, row_sha = saved
            row = json.loads(line)
            if (not 0 <= ordinal < len(order) or order[ordinal] != identifier or row['id'] != identifier
                    or hashlib.sha256(line[:-1]).hexdigest() != row_sha):
                raise ValueError('Exported candidate differs from its committed row.')
            if any(e['wire_sha256'] not in valid_responses for e in row['experts'] if e['execution'] != 'error'):
                raise ValueError('An expert decision has no recorded model response for its input.')
            yield row


def verify(run_id, port=8100, delivery=None, *, expect_full=False, checkpoint=False, allow_partial=False):
    if not re.fullmatch(r'moe-[A-Za-z0-9-]+', run_id):
        raise ValueError('Expected a scenario evaluation run ID.')
    url = f'http://127.0.0.1:{port}/api/item4/evaluation-runs/{run_id}'
    folder = runs.OUTPUT / run_id
    live = get_json(url)
    if checkpoint:
        if not expect_full:
            raise ValueError('Checkpoint audit requires --expect-full for its fixed reference population.')
        expected, manifest = source_cases(delivery, live, None, True)
        before = get_json(url)
        audit = audit_rows(checkpoint_rows(folder / 'records.sqlite3', live, expected), expected, manifest, run_id)
        after = get_json(url)
        matches = any(r['completed'] == audit['unique_scenarios'] and
                      all(r.get('progress', {}).get(k) == audit[k] for k in COUNTS) for r in (before, after))
        return dict(audit, mode='committed_checkpoint', live_completed_before=before['completed'],
                    live_completed_after=after['completed'], matches_observed_ledger_checkpoint=matches)
    report = get_json(url + '/report')
    local = json.loads((folder / 'report.json').read_bytes())
    terminal = {'completed', 'partial', 'failed'} if allow_partial else {'completed'}
    if report != live or report != local['ledger'] or report['status'] not in terminal:
        raise ValueError('The closed run, serving report and recorded ledger must match.')
    ledger_result = report.get('result', {})
    if expect_full and 'candidates_sha256' not in ledger_result:
        raise ValueError('The run ledger lacks the full-population output fingerprint.')
    download_hash = ledger_result.get('candidates_sha256', local['candidates_sha256'])
    with urlopen(url + '/candidates', timeout=300) as response:
        digest = hashlib.sha256()
        for block in iter(lambda: response.read(1024 * 1024), b''):
            digest.update(block)
    file = folder / 'candidates.jsonl'
    if not digest.hexdigest() == download_hash == local['candidates_sha256'] == runs.file_sha(file):
        raise ValueError('The downloaded candidate bytes differ from the sealed output.')
    expected, manifest = source_cases(delivery, report, local['selected_cves'], expect_full)
    if report.get('resumable') or expect_full:
        retry_counts = {}
        rows = exported_rows(folder, report, local['selected_cves'], expected,
                             local['unique_model_wire_cache_entries'], retry_counts)
        audit = audit_rows(rows, expected, manifest, run_id)
        audit['checked_model_cache_entries'] = local['unique_model_wire_cache_entries']
        if retry_counts['unique_retried_scenarios']:
            audit['retry_history'] = retry_counts
    else:
        with file.open(encoding='utf-8') as handle:
            audit = audit_rows(map(json.loads, handle), expected, manifest, run_id)
    if (audit['unique_scenarios'] != report['completed'] or
            audit['generation_statuses'].get('completed', 0) != report['candidate_count'] or report['expert_reviewed_count'] != 0 or
            (report['candidate_count'] and not audit['expert_executions']['model']) or
            audit['expert_executions'] != local['expert_executions']):
        raise ValueError('The downloaded results do not reproduce the closed run.')
    if (expect_full or report['status'] == 'completed') and audit['missing_scenarios']:
        raise ValueError('At least one requested scenario has no submitted row.')
    if report['status'] == 'completed' and audit['generation_statuses'] != {'completed':report['total']}:
        raise ValueError('A completed run requires a generated candidate for every scenario.')
    for key in COUNTS:
        if key in local and audit[key] != local[key]:
            raise ValueError('Downloaded counts disagree with the artifact report: ' + key)
        if key in ledger_result or expect_full:
            if (audit[key] != ledger_result.get(key) or audit[key] != local.get(key) or
                    audit[key] != report.get('progress', audit).get(key)):
                raise ValueError('Downloaded counts disagree with the run and report: ' + key)
    return dict(audit, mode=report['status'] + '_run', candidates_sha256=download_hash,
                ledger_output_sha256_recorded='candidates_sha256' in ledger_result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_id')
    parser.add_argument('--port', type=int, default=8100)
    parser.add_argument('--delivery', type=Path, help='Location of the pinned original V3 delivery.')
    parser.add_argument('--expect-full', action='store_true', help='Require all 12,418 CVEs and 97,553 cases in the run plan.')
    parser.add_argument('--checkpoint', action='store_true', help='Read committed rows during a full run.')
    parser.add_argument('--allow-partial', action='store_true', help='Verify terminal partial or failed traces and their separate execution errors.')
    parser.add_argument('--v1-rejections', action='store_true', help='Audit the 3,640 historical V1 rejections inside a closed full-population export.')
    parser.add_argument('--output', type=Path, help='Write the complete verification receipt to a new file.')
    args = parser.parse_args()
    if args.v1_rejections and args.checkpoint:
        parser.error('The V1 cohort audit requires a final export.')
    receipt = (verify_v1(args.run_id, args.port, args.delivery) if args.v1_rejections else
               verify(args.run_id, args.port, args.delivery, expect_full=args.expect_full,
                      checkpoint=args.checkpoint, allow_partial=args.allow_partial))
    if args.output:
        with args.output.open('x', encoding='utf-8') as f:
            json.dump(receipt, f, indent=2)
        print(f"Verified {receipt['unique_scenarios']:,} scenarios. {args.output}")
    else:
        print(json.dumps(receipt, indent=2))
