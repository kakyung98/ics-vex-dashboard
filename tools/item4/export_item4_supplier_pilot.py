"""Fill the frozen v2 export's documented gaps with independently checked pilot rows."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation.bulk_scenario_runner import atomic_json
from tools.item4.run_item4_supplier_pilot import PARENT, OUTPUT
from tools.item4.verify_item4_supplier_pilot import verify


def publish_file(temporary, target, digest):
    if runs.file_sha(temporary) != digest:
        raise ValueError('Written artifact does not match the expected fingerprint.')
    if target.exists():
        if runs.file_sha(target) != digest:
            raise ValueError('An existing artifact has a different fingerprint: ' + target.name)
    else:
        temporary.replace(target)


def export(parent, pilot):
    parent_report = json.loads((parent / 'report.json').read_bytes())
    source = pilot / 'pilot_candidates.jsonl'
    receipt = json.loads((pilot / 'independent_verification.json').read_bytes())
    if verify(parent, source) != receipt:
        raise ValueError('The current independent check does not reproduce the sealed pilot audit.')
    pilot_report = json.loads((pilot / 'report.json').read_bytes())
    if (receipt['run_id'] != pilot_report['run_id'] or receipt['candidates_sha256'] != pilot_report['candidates_sha256']
            or any(receipt['control_mismatches'].values())):
        raise ValueError('The pilot scope or control results do not support this supplement.')
    pilot_rows = {}
    control_ids = set()
    for line in source.read_bytes().splitlines(keepends=True):
        row = json.loads(line)
        if row['cohort'] == 'control':
            control_ids.add(row['id'])
        elif row['cohort'] == 'failure' and row['generation_status'] == 'completed':
            pilot_rows[row['id']] = (row, line)
        else:
            raise ValueError('Found an unvalidated or out-of-scope supplement.')
    original, mixed, preserved = (hashlib.sha256() for _ in range(3))
    seen = set()
    cves = set()
    counts = ledger.ProgressCounts()
    num_parent = 0
    num_pilot = 0
    name = None
    try:
        with NamedTemporaryFile(dir=pilot, suffix='.jsonl.tmp', delete=False) as out, (parent / 'candidates.jsonl').open('rb') as src:
            name = Path(out.name)
            for line in src:
                original.update(line)
                row = json.loads(line)
                identifier = row['id']
                if (identifier in seen or row['run_id'] != parent.name or row['synthetic'] is not True
                        or row['expert_validated'] is not False or row['label_kind'] != 'scenario_candidate'):
                    raise ValueError('Duplicate or invalid source row.')
                seen.add(identifier)
                cves.add(row['cve'])
                if row['generation_status'] == 'completed':
                    if identifier in pilot_rows:
                        raise ValueError('A replacement would overwrite a completed parent candidate.')
                    num_parent += 1
                    preserved.update(line)
                else:
                    new, replacement = pilot_rows.pop(identifier)
                    if (new['parent_row_sha256'] != hashlib.sha256(line.rstrip(b'\r\n')).hexdigest()
                            or new['packet_sha256'] != row['packet_sha256'] or new['cve'] != row['cve']
                            or new['run_id'] != receipt['run_id'] or new['parent_run_id'] != parent.name):
                        raise ValueError('Replacement does not match the specific original failure.')
                    num_pilot += 1
                    row, line = new, replacement
                counts.add(row)
                mixed.update(line)
                out.write(line)
            out.flush()
            os.fsync(out.fileno())
        if (original.hexdigest() != receipt['parent_candidates_sha256'] or pilot_rows
                or not control_ids.issubset(seen) or len(seen) != parent_report['ledger']['total']
                or len(cves) != parent_report['represented_cve_count'] or num_parent != parent_report['ledger']['candidate_count']
                or num_pilot != receipt['cohorts']['failure']):
            raise ValueError('Mixed export does not account for the complete parent and verified supplement.')
        summary = dict(kind='mixed_version_candidate_export', parent_run_id=parent.name, pilot_run_id=receipt['run_id'],
                       parent_candidates_sha256=original.hexdigest(), pilot_candidates_sha256=receipt['candidates_sha256'],
                       combined_candidates_sha256=mixed.hexdigest(), preserved_parent_rows_sha256=preserved.hexdigest(),
                       unique_scenarios=len(seen), unique_cves=len(cves), parent_rows_preserved=num_parent,
                       pilot_rows_used=num_pilot, controls_replaced=0, independent_expert_reviews=0, **counts.snapshot())
        publish_file(name, pilot / 'all_candidates.jsonl', mixed.hexdigest())
        atomic_json(pilot / 'coverage.json', summary)
        return summary
    finally:
        if name is not None:
            name.unlink(missing_ok=True)


def register_pilot(parent, pilot):
    """Publish only the actual 89-case pilot in the shared ledger. The composite is a file export."""
    report = json.loads((pilot / 'report.json').read_bytes())
    rid = report['run_id']
    audit = json.loads((pilot / 'independent_verification.json').read_bytes())
    candidate = pilot / 'pilot_candidates.jsonl'
    digest = runs.file_sha(candidate)
    if digest != report['candidates_sha256'] or digest != audit['candidates_sha256'] or audit['run_id'] != rid:
        raise ValueError('Pilot output differs from the independent verification.')
    counts = ledger.ProgressCounts()
    for line in candidate.read_bytes().splitlines():
        counts.add(json.loads(line))
    result = dict(candidates_sha256=digest, **counts.snapshot())
    if any(report[key] != value for key, value in result.items()):
        raise ValueError('The pilot report and candidate counts disagree.')
    current_parent = ledger.get_run(parent.name)
    if current_parent['result']['candidates_sha256'] != audit['parent_candidates_sha256']:
        raise ValueError('The registered parent is not the verified v2 baseline.')
    settings = dict(generation_method='scenario_moe_supplier_review_pilot', total=audit['unique_scenarios'],
                    model_hashes=current_parent['model_hashes'], code_hashes=report['code_hashes'],
                    data_hashes={'parent v2 candidates': audit['parent_candidates_sha256'],
                                 'supplier requests': report['requests_sha256'], 'supplier model responses': report['responses_sha256'],
                                 'independent pilot check': runs.file_sha(pilot / 'independent_verification.json')})
    # Use the same candidate file layout as other scenario ledger entries.
    directory = runs.OUTPUT / rid
    directory.mkdir(exist_ok=True)
    with NamedTemporaryFile(dir=directory, delete=False) as stream:
        temp = Path(stream.name)
        stream.write(candidate.read_bytes())
    try:
        publish_file(temp, directory / 'candidates.jsonl', digest)
    finally:
        temp.unlink(missing_ok=True)
    try:
        existing = ledger.get_run(rid)
    except KeyError:
        ledger.start_run(rid, **settings, resumable=True)
    else:
        if any(existing[k] != v for k, v in settings.items()):
            raise ValueError('An existing ledger entry has different provenance.')
        if existing['status'] == 'completed':
            if existing['result'] != result:
                raise ValueError('Existing completed ledger differs from the verified pilot.')
            return existing
        ledger.resume_run(rid, **settings)
    return ledger.update_run(rid, completed=audit['unique_scenarios'], candidate_count=sum(result['candidate_statuses'].values()),
                             status='completed', progress=counts.snapshot(), result=result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, default=PARENT)
    parser.add_argument('--pilot', type=Path, default=OUTPUT)
    args = parser.parse_args()
    parent, pilot = args.parent.resolve(), args.pilot.resolve()
    coverage = export(parent, pilot)
    registered = register_pilot(parent, pilot)
    print(json.dumps(dict(run_id=registered['run_id'], **coverage), ensure_ascii=False, indent=2))
