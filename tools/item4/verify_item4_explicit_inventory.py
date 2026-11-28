"""Verify the complete inventory-policy revision against the frozen operator inputs and prior mixed export."""
import argparse
from collections import Counter
from contextlib import closing
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.workflow.source_analysis_jobs import inventory

HISTORY = ROOT / 'results/item4_supplier_review_20261122'
BASELINE = ROOT / 'results/item4_extracted_ox_v3_20261120/verification.json'
RUNS = ROOT / 'results/item4_scenario_moe'
PREFIX = 'benchmark/item4_evaluation/extracted_ox_v3'
# Prior receipts pin both the original mixed JSONL and the operator-input manifest.
MIXED_RECEIPT_SHA = 'f1185c7635f23a9d231ef32d4249b14ce855489dfdfaada8d5721bf0f57bc65c'
PARENT_REPORT_SHA = '257b708646ad071d424fc3254d6368b804bf94ede9dac990c07ec9ed2b78e056'
OUTCOMES = ('affected', 'not_affected', 'fixed', 'under_investigation')
VERSION = 'item4-scenario-explicit-inventory/1'
HOLD = 'inventory_completeness_not_evidenced'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sealed(path, expected):
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, f'Sealed file differs: {path}')
    return json.loads(raw)


def frozen_inputs(delivery, manifest, archive_sha):
    """Compare aggregate inputs to the actual per-CVE invocation cases, including all supplied context."""
    input_name = f'{PREFIX}/inputs.jsonl'
    inputs_sha = hashlib.sha256()
    pending = {}
    with (delivery / input_name).open('rb') as stream:
        for line in stream:
            inputs_sha.update(line)
            case = json.loads(line)
            require(case['id'] not in pending and case['synthetic'] is True, 'Duplicate or invalid original input.')
            line_sha = hashlib.sha256(line.rstrip(b'\r\n')).hexdigest()
            pending[case['id']] = (case, line_sha)
    require(inputs_sha.hexdigest() == manifest[input_name], 'The aggregate input fingerprint differs.')
    pop_name = f'{PREFIX}/population_ledger.json'
    population = sealed(delivery / pop_name, manifest[pop_name])['cves']
    require(len(set(population)) == len(population) == 12418, 'The frozen CVE population differs.')
    staged = Path(tempfile.gettempdir()) / 'ICS-VEX/moe-inputs' / (archive_sha + '.sqlite3')
    connection = sqlite3.connect(staged.as_uri() + '?mode=ro&immutable=1', uri=True) if staged.is_file() else None
    contexts = {}
    scopes = {}
    try:
        for cve in population:
            name = f'{PREFIX}/cves/{cve}.json'
            if connection is None:
                packet = sealed(delivery / name, manifest[name])
            else:
                with closing(connection.execute('SELECT packet FROM packets WHERE cve=?', (cve,))) as query:
                    stored = query.fetchone()
                require(stored is not None, f'Missing frozen invocation packet: {cve}')
                raw = zlib.decompress(stored[0])
                require(hashlib.sha256(raw).hexdigest() == manifest[name], f'Changed invocation packet: {cve}')
                packet = json.loads(raw)
            require(packet['cve'] == cve and packet['cases'], f'Invalid packet: {cve}')
            components, declarations = inventory(packet['job']['input_bom'])
            declaration, = [item for item in declarations if item['cve'] == cve]
            ref, = declaration['component_refs']
            component, = [item['value'] for item in components if item['ref'] == ref]
            scopes[cve] = (ref, component.get('version') or component.get('versionInfo'), manifest[name])
            for case in packet['cases']:
                identifier = case['id']
                original, line_sha = pending.pop(identifier, (None, None))
                require(case == original and case['cve'] == cve, f'Invocation and aggregate inputs differ: {identifier}')
                contexts[identifier] = (cve, original['context'], line_sha)
    finally:
        if connection is not None:
            connection.close()
    require(not pending and len(contexts) == 97553, 'Original scenarios are missing or duplicated.')
    return contexts, scopes, inputs_sha.hexdigest()


def check_legacy_absence(row, context, scope):
    """Distinguish original raw coverage from the historical model's generated observation."""
    identifier = row['id']
    ref, version, packet_sha = scope
    product = row['verified_product']
    require((row['packet_sha256'], product['cve'], product['component_ref'], product['version'])
            == (packet_sha, row['cve'], ref, version), f'Original product or input scope differs: {identifier}')
    if context['deployment'] != 'not_deployed':
        return False
    require(context['scope'] == 'current_single' and ref and 'inventory_coverage' not in context,
            f'Original absence observation needs a new review: {identifier}')
    expert, = [e for e in row['experts'] if e['expert'] == 'inventory']
    observation = dict(scope=context['scope'], deployment=context['deployment'], runtime=context['runtime'],
                       complete_inventory=True, component_ref=ref, version=version)
    raw = json.dumps(observation, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
    eid = 'observation:' + hashlib.sha256(raw).hexdigest()
    require(expert['verdict'] == 'absent_complete' and expert['evidence_ids'] == [eid] and
            row['cited_evidence'].get(eid) == observation, f'Historical implicit coverage receipt differs: {identifier}')
    crosscheck, = [e for e in row['experts'] if e['expert'] == 'crosscheck']
    corroborated = crosscheck['verdict'] == 'corroborated' and eid in crosscheck['evidence_ids']
    expected = ('not_affected', []) if corroborated else ('under_investigation', ['crosscheck_did_not_corroborate'])
    require((row['candidate_status'], row['reasons']) == expected, f'Original absence adjudication differs: {identifier}')
    return True


def check_revision(row, prior, row_sha, case_sha, context, absent, run_id):
    identifier = prior['id']
    fields = dict(prior)
    new_input = json.dumps([VERSION, row_sha, case_sha], ensure_ascii=False, separators=(',', ':')).encode()
    fields.update(
        version=VERSION, run_id=run_id, input_sha256=hashlib.sha256(new_input).hexdigest(),
        source_decision=dict(run_id=prior['run_id'], version=prior['version'], input_sha256=prior['input_sha256'],
                             row_sha256=row_sha),
        inventory_review=dict(source_input_sha256=case_sha, scope=context['scope'], deployment=context['deployment'],
                              inventory_coverage_present='inventory_coverage' in context,
                              inventory_coverage=context.get('inventory_coverage'),
                              component_ref=prior['verified_product']['component_ref'],
                              decision='coverage_required' if absent else 'not_applicable'))
    if absent:
        fields.update(candidate_status='under_investigation', reasons=[HOLD], experts=[], routed_experts=[],
                      evidence_ids=[], cited_evidence={}, source_rule_identities=None, inference_role=None)
    else:
        fields['experts'] = [
            dict(expert, execution='cached', model_requested=False, model_called=False,
                 response_source='source_run_model_receipt')
            for expert in prior['experts']
        ]
    require(fields.keys() == row.keys(), f'Unexpected revision fields: {identifier}: {set(fields) ^ set(row)}')
    require(row['synthetic'] is True and row['expert_validated'] is False and
            row['inventory_review']['inventory_coverage_present'] is ('inventory_coverage' in context) and
            all(e['model_called'] is False and e['model_requested'] is False for e in row['experts']),
            f'Evidence or model attribution flags differ: {identifier}')
    for key, expected in fields.items():
        require(row[key] == expected, f'Revision differs from the source-backed decision in {key}: {identifier}')
    return sum(e['model_called'] is True for e in row['experts'])


def verify(run_folder, *, history=HISTORY, delivery=None, run_id=None):
    run_folder = Path(run_folder)
    history = Path(history)
    run_id = run_id or run_folder.name
    mixed = sealed(history / 'mixed_verification.json', MIXED_RECEIPT_SHA)
    coverage = sealed(history / 'coverage.json', mixed['coverage_sha256'])
    parent = sealed(RUNS / mixed['parent_run_id'] / 'report.json', PARENT_REPORT_SHA)['ledger']
    require(parent['run_id'] == mixed['parent_run_id'] and
            parent['result']['candidates_sha256'] == mixed['parent_candidates_sha256'] and
            mixed['combined_candidates_sha256'] == coverage['combined_candidates_sha256'],
            'Mixed output lineage conflicts with its independently sealed parent.')
    base = json.loads(BASELINE.read_bytes())
    delivery = Path(delivery or base['artifact_directory'])
    manifest_sha = parent['data_hashes']['v3 delivery manifest']
    manifest = sealed(delivery / 'delivery_manifest.json', manifest_sha)
    contexts, scopes, input_sha = frozen_inputs(delivery, manifest, base['archive']['sha256'])
    prior_statuses = Counter(dict.fromkeys(OUTCOMES, 0))
    statuses = prior_statuses.copy()
    prior_reasons, reasons, product_reasons = Counter(), Counter(), Counter()
    old_sha, new_sha, review_sha = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
    prior_runs, changed, missing_coverage_by_prior_status = Counter(), Counter(), Counter()
    matched = 0
    retained = 0
    fresh_calls = 0
    review_path = run_folder / 'prior_not_affected_review.jsonl'
    with (history / 'all_candidates.jsonl').open('rb') as old, (run_folder / 'candidates.jsonl').open('rb') as new, \
            review_path.open('rb') as reviews:
        for original_line, revised_line in zip_longest(old, new):
            require(original_line is not None and revised_line is not None, 'The output has missing or extra rows.')
            old_sha.update(original_line)
            new_sha.update(revised_line)
            prior = json.loads(original_line)
            row = json.loads(revised_line)
            identifier = prior['id']
            require(identifier == row['id'] and identifier in contexts, f'Reordered, extra, or duplicate ID: {identifier}')
            cve, context, case_sha = contexts.pop(identifier)
            require(prior['cve'] == cve and prior['synthetic'] is True and prior['expert_validated'] is False and
                    prior['label_kind'] == 'scenario_candidate' and prior['generation_status'] == 'completed',
                    f'Original identity or review status differs: {identifier}')
            absent = check_legacy_absence(prior, context, scopes[cve])
            prior_status = prior['candidate_status']
            require(prior_status != 'not_affected' or absent, f'Non-absence original negative requires review: {identifier}')
            if absent:
                missing_coverage_by_prior_status[prior_status] += 1
            else:
                retained += 1
            row_sha = hashlib.sha256(original_line.rstrip(b'\r\n')).hexdigest()
            fresh_calls += check_revision(row, prior, row_sha, case_sha, context, absent, run_id)
            final_status = row['candidate_status']
            if prior_status == 'not_affected':
                review_line = reviews.readline()
                require(review_line, f'Missing previous not_affected review: {identifier}')
                review_sha.update(review_line)
                decision = dict(id=identifier, cve=cve, previous_status=prior_status, candidate_status=final_status,
                                source_run_id=prior['run_id'], source_row_sha256=row_sha, source_input_sha256=case_sha,
                                candidate_row_sha256=hashlib.sha256(revised_line.rstrip(b'\r\n')).hexdigest(),
                                inventory_coverage_present='inventory_coverage' in context,
                                inventory_coverage=context.get('inventory_coverage'), reason=HOLD if absent else None)
                require(json.loads(review_line) == decision, f'Previous not_affected review differs: {identifier}')
            prior_statuses[prior_status] += 1
            prior_runs[prior['run_id']] += 1
            statuses[final_status] += 1
            if final_status != prior_status:
                changed[(prior_status, final_status)] += 1
            if prior_status == 'under_investigation':
                prior_reasons.update(set(prior['reasons']))
            if final_status == 'under_investigation':
                reasons.update(set(row['reasons']))
                if 'supplier_evidence_conflicting_or_unresolved' in row['reasons']:
                    product_reasons.update(set(row['product_reasons']))
            matched += 1
        require(not reviews.readline(), 'Extra or duplicate previous not_affected review.')
    require(not contexts and matched == mixed['unique_scenarios'] and len(scopes) == mixed['unique_cves'],
            'Source population does not match the complete output.')
    require(old_sha.hexdigest() == mixed['combined_candidates_sha256'] and
            prior_statuses == mixed['candidate_statuses'] and prior_reasons == mixed['hold_reasons'] and
            prior_runs == {mixed['parent_run_id']: mixed['byte_identical_parent_rows'],
                           mixed['pilot_run_id']: mixed['byte_identical_pilot_replacement_rows']},
            'Original mixed export differs from its independent receipt.')
    require(missing_coverage_by_prior_status == {'not_affected': 12029, 'under_investigation': 389} and
            changed == {('not_affected', 'under_investigation'): 12029} and fresh_calls == 0,
            'Disposition, evidence coverage, or model attribution differs from the requested revision.')
    return dict(kind='independent_explicit_inventory_full_verification', run_id=run_id,
                candidates_sha256=new_sha.hexdigest(), prior_candidates_sha256=old_sha.hexdigest(),
                prior_not_affected_review_sha256=review_sha.hexdigest(),
                source_mixed_receipt_sha256=MIXED_RECEIPT_SHA, source_manifest_sha256=manifest_sha,
                inputs_sha256=input_sha, unique_scenarios=matched, unique_cves=len(scopes),
                matched_packet_cases=matched, missing_ids=0, duplicate_ids=0, extra_ids=0, order_mismatches=0,
                previous_not_affected_reviewed=prior_statuses['not_affected'],
                previous_not_affected_retained=prior_statuses['not_affected'] - changed[('not_affected', 'under_investigation')],
                previously_held_reason_reclassified=missing_coverage_by_prior_status['under_investigation'],
                unchanged_decisions_and_reasons=retained, status_changed=sum(changed.values()),
                status_transitions={f'{old} -> {new}': count for (old, new), count in changed.items()},
                previous_statuses=dict(prior_statuses), candidate_statuses=dict(statuses),
                generation_statuses={'completed': matched}, hold_reasons=dict(reasons),
                product_hold_reasons=dict(product_reasons), gated_rows=sum(missing_coverage_by_prior_status.values()),
                gated_rows_by_prior_status=dict(missing_coverage_by_prior_status), retained_evidence_rows=retained,
                validated_prior_model_row_origins=dict(prior_runs), new_model_calls=fresh_calls, independent_expert_reviews=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_folder', type=Path)
    parser.add_argument('--delivery', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    receipt = verify(args.run_folder, delivery=args.delivery)
    encoded = json.dumps(receipt, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        if args.output.exists():
            require(json.loads(args.output.read_bytes()) == receipt, 'Existing independent receipt differs.')
        else:
            with args.output.open('x', encoding='utf-8', newline='\n') as stream:
                stream.write(encoded)
    print(encoded)
