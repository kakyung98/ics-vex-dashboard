"""Re-adjudicate the full, sealed scenario population with explicit inventory coverage."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.decision import inventory_evidence_policy as policy
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.models import scenario_review_experts as v2
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.evaluation.bulk_scenario_runner import encoded
from tools.item4.audit_item4_deployment_holds import component


HISTORY = ROOT / 'results/item4_supplier_review_20261122'
VERSION = 'item4-scenario-explicit-inventory/1'
METHOD = 'scenario_moe_explicit_inventory_review'
ORIGINAL_COVERAGE = '57ce29e7e6fd62443e2f8f0e468fc2e6c2b5c02de9df87457ab2e949bdcf92a9'
ORIGINAL_CHECK = 'f1185c7635f23a9d231ef32d4249b14ce855489dfdfaada8d5721bf0f57bc65c'
STATES = ('affected', 'not_affected', 'fixed', 'under_investigation')


def require(test, message):
    if not test:
        raise ValueError(message)


def sealed_handoff():
    coverage = runs.sealed_json(HISTORY / 'coverage.json', ORIGINAL_COVERAGE)
    audit = runs.sealed_json(HISTORY / 'mixed_verification.json', ORIGINAL_CHECK)
    require(coverage['combined_candidates_sha256'] == audit['combined_candidates_sha256']
            and audit['coverage_sha256'] == ORIGINAL_COVERAGE and not audit['missing_ids']
            and not audit['duplicate_ids'] and not audit['extra_ids'], 'Invalid source export verification.')
    source_ids = [coverage['parent_run_id'], coverage['pilot_run_id']]
    for rid, name in zip(source_ids, ('parent_candidates_sha256', 'pilot_candidates_sha256')):
        require(ledger.get_run(rid)['result']['candidates_sha256'] == coverage[name],
                'Source run has a different artifact fingerprint: ' + rid)
    return coverage, source_ids


def load_observations(parent, delivery):
    pins = parent['data_hashes']
    manifest = runs.sealed_json(delivery / 'delivery_manifest.json', pins['v3 delivery manifest'])
    key = runs.PREFIX + '/inputs.jsonl'
    observations = {}
    digest = hashlib.sha256()
    with (delivery / key).open('rb') as stream:
        for line in stream:
            digest.update(line)
            record = json.loads(line)
            require(record['id'] not in observations and record['synthetic'] is True and
                    isinstance(record['context'], dict), 'Duplicate or invalid source observation.')
            observations[record['id']] = (record['cve'], record['context'], runs.sha(line.rstrip(b'\r\n')))
    require(digest.hexdigest() == manifest[key] and len(observations) == parent['total'], 'Frozen input differs.')
    return manifest, observations, digest.hexdigest()


def project(old, context, input_sha, parent_sha, run_id):
    ref = old['verified_product']['component_ref']
    reason = policy.absence_hold_reason(context, ref)
    absence = context.get('deployment') == 'not_deployed'
    review = dict(source_input_sha256=input_sha, scope=context.get('scope'), deployment=context.get('deployment'),
                  inventory_coverage_present='inventory_coverage' in context,
                  inventory_coverage=context.get('inventory_coverage'), component_ref=ref,
                  decision='coverage_required' if reason else 'explicit_complete' if absence else 'not_applicable')
    row = dict(old, version=VERSION, run_id=run_id, input_sha256=v2.digest([VERSION, parent_sha, input_sha]),
               source_decision={k: old[k] for k in ('run_id','version','input_sha256')}, inventory_review=review)
    row['source_decision']['row_sha256'] = parent_sha
    if reason:
        # The historical inventory/cross-check receipts refer to a different observation.
        # Keep their exact source address above. They are not active evidence for this decision.
        row.update(candidate_status='under_investigation', reasons=[reason], evidence_ids=[], cited_evidence={},
                   experts=[], routed_experts=[], inference_role=None, source_rule_identities=None)
    else:
        row['experts'] = [dict(e, execution='cached', model_called=False, model_requested=False,
                               response_source='source_run_model_receipt') for e in old['experts']]
    return row


def review_all(directory, run_id, history, parent, manifest, observations, input_sha, source, hashes):
    population = runs.sealed_json(history / (runs.PREFIX + '/population_ledger.json'),
                                  parent['data_hashes']['frozen CVE population'])
    expected_cves = set(population['cves'])
    observed_components = {}
    transitions = defaultdict(Counter)
    absence = Counter(dict.fromkeys(('reviewed','explicit_complete','missing','partial','other',
                                      'already_under_investigation','prior_crosscheck_holds_replaced'), 0))
    previous_negative = Counter(dict.fromkeys(('reviewed','retained','changed_to_under_investigation'), 0))
    coverage_values = Counter()
    previous, revised = ledger.ProgressCounts(), ledger.ProgressCounts()
    prior_sources = Counter()
    source_hash = hashlib.sha256()
    baseline = json.loads(runs.BASELINE.read_bytes())
    spool = Path(tempfile.gettempdir())/'ICS-VEX/moe-inputs'/(baseline['archive']['sha256'] + '.sqlite3')
    packet_location = spool if spool.is_file() else history
    candidates = directory / 'candidates.jsonl'
    rechecks = directory / 'prior_not_affected_review.jsonl'
    with (HISTORY / 'all_candidates.jsonl').open('rb') as src, candidates.open('xb') as out, rechecks.open('xb') as checks:
        for line in src:
            source_hash.update(line)
            old = json.loads(line)
            identifier, cve = old['id'], old['cve']
            src_cve, context, case_sha = observations.pop(identifier)
            require(cve == src_cve and old['run_id'] in (source['parent_run_id'], source['pilot_run_id'])
                    and old['generation_status'] == 'completed' and old['synthetic'] is True
                    and old['expert_validated'] is False and old['label_kind'] == 'scenario_candidate',
                    'A source case is outside the verified candidate cohort.')
            if cve not in observed_components:
                packet = runs.input_packet(packet_location, manifest, cve)
                observed_components[cve] = component(packet)
            product = old['verified_product']
            require(product['cve'] == cve and observed_components[cve] == (product['component_ref'], product['version'])
                    and old['packet_sha256'] == manifest[f'{runs.PREFIX}/cves/{cve}.json'],
                    'Product or source packet scope does not match.')
            prior_status = old['candidate_status']
            parent_sha = runs.sha(line.rstrip(b'\r\n'))
            new = project(old, context, case_sha, parent_sha, run_id)
            active = new['candidate_status']
            raw = encoded(new)
            out.write(raw + b'\n')
            previous.add(old)
            revised.add(new)
            transitions[prior_status][active] += 1
            review = new['inventory_review']
            if review['decision'] != 'not_applicable':
                absence['reviewed'] += 1
                observed = review['inventory_coverage']
                key = ('missing' if not review['inventory_coverage_present'] else 'explicit_complete' if observed == 'complete'
                       else 'partial' if observed == 'partial' else 'other')
                absence[key] += 1
                absence['already_under_investigation'] += prior_status == 'under_investigation'
                absence['prior_crosscheck_holds_replaced'] += (review['decision'] == 'coverage_required' and
                                                               'crosscheck_did_not_corroborate' in old['reasons'])
            if prior_status == 'not_affected':
                previous_negative['reviewed'] += 1
                previous_negative['retained'] += active == 'not_affected'
                previous_negative['changed_to_under_investigation'] += active == 'under_investigation'
                prior_sources[old['run_id']] += 1
                coverage_values[str(review['inventory_coverage']) if review['inventory_coverage_present'] else '<missing>'] += 1
                checks.write(encoded(dict(id=identifier, cve=cve, previous_status=prior_status, candidate_status=active,
                                          source_run_id=old['run_id'], source_row_sha256=parent_sha, source_input_sha256=case_sha,
                                          candidate_row_sha256=runs.sha(raw), inventory_coverage_present=review['inventory_coverage_present'],
                                          inventory_coverage=review['inventory_coverage'],
                                          reason=policy.MISSING_COMPLETENESS if review['decision']=='coverage_required' else None)) + b'\n')
    require(not observations and observed_components.keys() == expected_cves
            and source_hash.hexdigest() == source['combined_candidates_sha256']
            and all(source[k] == v for k, v in previous.snapshot().items()), 'Incomplete or modified source population.')
    snapshot = revised.snapshot()
    return dict(run_id=run_id, version=VERSION, generation_method=METHOD, unique_scenarios=source['unique_scenarios'],
                unique_cves=len(expected_cves), synthetic=True, expert_validated=False, additional_model_calls=0,
                independent_expert_reviews=0, code_hashes=hashes, candidates_sha256=runs.file_sha(candidates),
                prior_not_affected_review_sha256=runs.file_sha(rechecks), source_candidates_sha256=source_hash.hexdigest(),
                inputs_sha256=input_sha, source_manifest_sha256=parent['data_hashes']['v3 delivery manifest'],
                source_run_ids=[source['parent_run_id'],source['pilot_run_id']], source_artifact='item4_supplier_review_20261122/all_candidates.jsonl',
                source_coverage_field='/context/inventory_coverage', previous_hold_reasons=source['hold_reasons'],
                previous_candidate_statuses={k:source['candidate_statuses'].get(k,0) for k in STATES},
                prior_not_affected_review=dict(previous_negative, coverage_values=coverage_values, source_runs=prior_sources),
                absence_evidence_review=absence, transitions=transitions, **snapshot)


def build():
    coverage, source_ids = sealed_handoff()
    parent = ledger.get_run(source_ids[0])
    delivery = Path(json.loads(runs.BASELINE.read_bytes())['artifact_directory'])
    manifest, observations, inputs = load_observations(parent, delivery)
    code = review_code_hashes()
    rid = 'moe-inventory-review-' + v2.digest([VERSION, coverage['combined_candidates_sha256'], inputs, code])[:18]
    root = runs.OUTPUT.resolve()
    dest = root / rid
    with tempfile.TemporaryDirectory(dir=root, prefix='.inventory-review-') as stage:
        working = Path(stage) / rid
        working.mkdir()
        summary = review_all(working, rid, delivery, parent, manifest, observations, inputs, coverage, code)
        (working/'report.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        try:
            working.rename(dest)
        except OSError:
            if not dest.is_dir() or any(runs.file_sha(dest/p.name) != runs.file_sha(p) for p in working.iterdir()):
                raise
    print(str(dest))


def review_code_hashes():
    return {p.name: runs.file_sha(p) for p in
            (Path(__file__), Path(policy.__file__), ROOT / 'tools/item4/audit_item4_deployment_holds.py')}


def publish(directory):
    from tools.item4.verify_item4_explicit_inventory import verify
    from tools.item4.render_item4_inventory_review import verify_totals
    report_file = directory / 'report.json'
    report = json.loads(report_file.read_bytes())
    rid = report['run_id']
    require(directory == (runs.OUTPUT/rid).resolve() and report['version'] == VERSION, 'Unexpected report directory or version.')
    saved_audit = json.loads((directory/'independent_verification.json').read_bytes())
    require(verify(directory) == saved_audit, 'Independent audit differs from the recorded verification.')
    require(review_code_hashes() == report['code_hashes'], 'The adjudicating code changed after this review.')
    verify_totals(report, saved_audit, directory)
    coverage, source_ids = sealed_handoff()
    source = ledger.get_run(source_ids[0])
    require(report['source_candidates_sha256'] == coverage['combined_candidates_sha256']
            and runs.file_sha(directory/'candidates.jsonl') == report['candidates_sha256']
            and runs.file_sha(directory/'prior_not_affected_review.jsonl') == report['prior_not_affected_review_sha256'],
            'Revised output fingerprints do not match.')
    files = {name:runs.file_sha(directory/name) for name in
             ('report.json', 'report.ko.html', 'prior_not_affected_review.jsonl', 'independent_verification.json')}
    settings = dict(generation_method=METHOD, total=report['unique_scenarios'], code_hashes=report['code_hashes'],
                    model_hashes=source['model_hashes'], data_hashes=dict(files, source_candidates=report['source_candidates_sha256'],
                        frozen_scenario_inputs=report['inputs_sha256'], frozen_source_manifest=report['source_manifest_sha256']))
    progress = {k:report[k] for k in ledger.COUNT_KEYS}
    result = dict(progress, candidates_sha256=report['candidates_sha256'])
    review = {key: report[key] for key in ('prior_not_affected_review', 'absence_evidence_review',
                                           'previous_candidate_statuses', 'transitions', 'additional_model_calls')}
    try:
        existing = ledger.get_run(rid)
    except KeyError:
        ledger.start_run(rid, **settings, resumable=True)
    else:
        require(all(existing[k] == v for k,v in settings.items()), 'Existing ledger provenance differs.')
        if existing['status'] == 'completed':
            require(existing['result'] == result and existing.get('inventory_review') == review,
                    'Existing ledger results differ.')
        else:
            ledger.resume_run(rid, **settings)
    ledger.update_run(rid, completed=report['unique_scenarios'], candidate_count=sum(progress['candidate_statuses'].values()),
                      status='completed', progress=progress, result=result, inventory_review=review)
    latest = dict(run_id=rid, generation_method=METHOD, candidates=f'{rid}/candidates.jsonl', candidates_sha256=report['candidates_sha256'],
                  report=f'{rid}/report.ko.html', report_sha256=files['report.ko.html'])
    with tempfile.NamedTemporaryFile(dir=runs.OUTPUT, mode='wb', delete=False) as stream:
        tmp = Path(stream.name)
        stream.write(json.dumps(latest, indent=2).encode()+b'\n')
    try:
        os.replace(tmp, runs.OUTPUT / 'current_full_population.json')
    finally:
        tmp.unlink(missing_ok=True)
    print(json.dumps(latest, indent=2))


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest='action', required=True)
    sub.add_parser('build')
    sub.add_parser('publish').add_argument('directory', type=Path)
    args = cli.parse_args()
    if args.action == 'build':
        build()
    else:
        publish(args.directory.resolve())
