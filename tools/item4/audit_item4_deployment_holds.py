"""Recount deployment/version holds against the frozen operator inputs and scoped inventory receipts."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.item4.models import scenario_review_experts as v2
from src.item4.evaluation import scenario_evaluation_runner as runs
from src.item4.analysis.product_advisory_evidence import component_identity
from src.item4.workflow.source_analysis_jobs import inventory

MIXED = ROOT / 'results/item4_supplier_review_20261122'
HOLD = 'deployment_or_running_version_unresolved'
FIELDS = ('scope', 'deployment', 'runtime', 'inventory_coverage')


def check(ok, message):
    if not ok:
        raise ValueError(message)


def component(packet):
    components, declarations = inventory(packet['job']['input_bom'])
    target = next((d for d in declarations if d['cve'] == packet['cve']), {})
    refs = target.get('component_refs', [])
    matches = [c for c in components if c['ref'] in refs]
    if len(refs) != 1 or len(matches) != 1:
        return None, None
    ident = component_identity(matches[0])
    return ident['ref'], ident['version']


def classify(values, has_ref, complete, verdict):
    scope, deployment, runtime = (values[k] for k in ('scope', 'deployment', 'runtime'))
    if scope != 'current_single':
        return 'scope_' + scope, None
    if not has_ref:
        return 'missing_component_ref', None
    if deployment == 'not_deployed':
        if not complete:
            return 'absence_coverage_incomplete', None
        return (None if verdict == 'absent_complete' else 'absence_model_not_confirmed'), 'complete_absence'
    if deployment != 'running':
        return 'deployment_' + deployment, None
    if runtime != 'bom':
        return 'runtime_' + runtime, None
    return (None if verdict == 'installed_exact' else 'installed_model_not_confirmed'), 'exact_installation'


def audit(folder, delivery=None):
    baseline = json.loads(runs.BASELINE.read_bytes())
    delivery = Path(delivery or baseline['artifact_directory'])
    coverage = json.loads((folder / 'coverage.json').read_bytes())
    mixed_check = json.loads((folder / 'mixed_verification.json').read_bytes())
    parent = json.loads((runs.OUTPUT / coverage['parent_run_id'] / 'report.json').read_bytes())
    pins = parent['ledger']['data_hashes']
    check(coverage['combined_candidates_sha256'] == mixed_check['combined_candidates_sha256'] and
          runs.file_sha(ROOT / 'src/item4/models/scenario_review_experts.py') == parent['ledger']['code_hashes']['item4_scenario_moe.py'],
          'The mixed export or frozen v2 gate differs from its verification receipt.')
    manifest = runs.sealed_json(delivery / 'delivery_manifest.json', pins['v3 delivery manifest'])
    name = runs.PREFIX + '/inputs.jsonl'
    source_sha, combined_sha = hashlib.sha256(), hashlib.sha256()
    contexts = {}
    with (delivery / name).open('rb') as source:
        for line in source:
            source_sha.update(line)
            case = json.loads(line)
            check(case['id'] not in contexts and case['synthetic'] is True, 'Invalid or duplicate frozen input.')
            contexts[case['id']] = (case['cve'], case['context'])
    check(source_sha.hexdigest() == manifest[name] and len(contexts) == coverage['unique_scenarios'],
          'Frozen scenario count or content differs.')
    spool = Path(tempfile.gettempdir()) / 'ICS-VEX/moe-inputs' / (baseline['archive']['sha256'] + '.sqlite3')
    source_location = spool if spool.is_file() else delivery

    # Recover the exact frozen inventory template without invoking a model.
    template = {}
    def capture(system, packet, *, role):
        template.update(system=system, packet=packet)
        return {}
    v2._expert('inventory', [('observation', {})], capture, None)
    packet = template['packet']
    raw_counts = {field: Counter() for field in (*FIELDS, 'component_ref_presence', 'inventory_verdict')}
    causes, refs, coverage_basis = Counter(), Counter(), Counter()
    absence_coverage = Counter(explicit_complete=0, synthetic_not_deployed_default=0)
    eligible = {s: {branch: Counter(input_eligible=0, model_confirmed=0, model_not_confirmed=0)
                    for branch in ('complete_absence', 'exact_installation')} for s in ('all_scenarios', 'held_scenarios')}
    assets, held_cves = {}, set()
    n = 0
    with (folder / 'all_candidates.jsonl').open('rb') as mixed:
        for line in mixed:
            combined_sha.update(line)
            row = json.loads(line)
            identifier, cve = row['id'], row['cve']
            check(identifier in contexts, 'Duplicate or unexpected candidate ID.')
            src_cve, context = contexts.pop(identifier)
            check(src_cve == cve and row['synthetic'] is True and row['generation_status'] == 'completed',
                  'Candidate and synthetic source identity differ.')
            if cve not in assets:
                assets[cve] = component(runs.input_packet(source_location, manifest, cve))
            ref, version = assets[cve]
            product = row['verified_product']
            check((product['cve'], product['component_ref'], product['version']) == (cve, ref, version) and
                  row['packet_sha256'] == manifest[f'{runs.PREFIX}/cves/{cve}.json'], 'Scoped BOM evidence differs.')
            values = {k: context.get(k) if context.get(k) in v2.CONTEXT_OPTIONS[k] else 'unknown' for k in FIELDS}
            legacy_complete = 'inventory_coverage' not in context and values['deployment'] == 'not_deployed'
            complete = values['inventory_coverage'] == 'complete' or legacy_complete
            observation = {k: values[k] for k in ('scope', 'deployment', 'runtime')}
            observation.update(complete_inventory=complete, component_ref=ref, version=version)
            eid = 'observation:' + v2.digest(observation)
            packet['evidence'] = {'e0': observation}
            fingerprint = v2.digest([v2.VERSION, v2.INFERENCE_ROLE, template['system'], packet, {'e0': eid}])
            wire = v2.digest([v2.VERSION, v2.INFERENCE_ROLE, template['system'], json.dumps(packet, ensure_ascii=False)])
            [expert] = [e for e in row['experts'] if e['expert'] == 'inventory']
            verdict = expert['verdict']
            check(expert['input_sha256'] == fingerprint and expert['wire_sha256'] == wire and
                  expert['execution'] in {'model','cached'} and expert['llm_used'] is True and
                  verdict in v2.CHOICES['inventory'], 'Inventory receipt differs from the reconstructed observation.')
            cause, branch = classify(values, bool(ref), complete, verdict)
            held = row['candidate_status'] == v2.UNKNOWN and HOLD in row['reasons']
            check(bool(cause) == held, 'Replayed inventory gate does not match the recorded hold.')
            if branch == 'complete_absence':
                absence_coverage['synthetic_not_deployed_default' if legacy_complete else 'explicit_complete'] += 1
            if branch:
                for group in (('all_scenarios','held_scenarios') if held else ('all_scenarios',)):
                    eligible[group][branch]['input_eligible'] += 1
                    eligible[group][branch]['model_not_confirmed' if held else 'model_confirmed'] += 1
            n += 1
            if held:
                causes[cause] += 1
                held_cves.add(cve)
                if ref:
                    refs[ref] += 1
                for field in FIELDS:
                    raw_counts[field][context.get(field, '<missing>')] += 1
                raw_counts['component_ref_presence']['present' if ref else 'missing'] += 1
                raw_counts['inventory_verdict'][verdict] += 1
                coverage_basis['synthetic_not_deployed_default' if legacy_complete else
                               'explicit_complete' if complete else 'incomplete_or_unavailable'] += 1
    held_count = sum(causes.values())
    check(not contexts and n == 97553 and len(assets) == 12418 and
          combined_sha.hexdigest() == coverage['combined_candidates_sha256'] and
          held_count == coverage['hold_reasons'][HOLD] == 53758 and
          all(sum(counter.values()) == held_count for counter in raw_counts.values()), 'Incomplete diagnostic coverage.')
    return dict(kind='frozen_deployment_hold_diagnostic', parent_run_id=coverage['parent_run_id'],
                pilot_run_id=coverage['pilot_run_id'], inputs_sha256=source_sha.hexdigest(),
                combined_candidates_sha256=combined_sha.hexdigest(), source_manifest_sha256=pins['v3 delivery manifest'],
                inventory_gate_sha256=parent['ledger']['code_hashes']['item4_scenario_moe.py'],
                unique_scenarios=n, unique_cves=len(assets), duplicate_ids=0, missing_ids=0,
                held_scenarios=held_count, held_cves=len(held_cves), unit='synthetic scenarios',
                precedence=['scope','component_ref','deployment','absence_coverage_or_running_version','inventory_verdict'],
                first_cause_counts=causes, raw_field_counts=raw_counts, effective_inventory_coverage_basis=coverage_basis,
                complete_absence_input_coverage_sources=absence_coverage,
                unique_nonempty_component_refs_in_holds=len(refs), eligible_inventory_checks=eligible,
                matched_inventory_input_receipts=n, additional_model_calls=0, changed_candidate_rows=0)


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--folder', type=Path, default=MIXED)
    cli.add_argument('--delivery', type=Path)
    cli.add_argument('--output', type=Path)
    args = cli.parse_args()
    data = audit(args.folder, args.delivery)
    text = json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with args.output.open('x', encoding='utf-8') as f:
            f.write(text)
    print(text)
