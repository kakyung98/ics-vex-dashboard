"""Generate review candidates for the frozen #4 operator scenarios, without reading labels."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid

from src.item4.decision import scoped_vex_review as asset_vulntology; from src.item4.analysis import product_advisory_evidence as item4_advisory_context; from src.item4.workflow import source_analysis_jobs as item4_questionnaire
from src.item4.evaluation import evaluation_run_records as ledger
from src.item4.decision import inventory_evidence_policy as candidate_policy
from src.item4.models import scenario_review_experts as item4_scenario_moe; from src.item4.models import json_inference_client as prerequisite_llm
from src.item4.evaluation.operator_observation_benchmark import source_bindings


ROOT = Path(__file__).resolve().parents[3]
BASELINE = ROOT / 'results/item4_extracted_ox_v3_20261120/verification.json'
REPLAY = ROOT / 'results/item4_fixed_world_replay_20261121'
OUTPUT = ROOT / 'results/item4_scenario_moe'
PREFIX = 'benchmark/item4_evaluation/extracted_ox_v3'
CODE = ('item4_scenario_run', 'item4_scenario_moe', 'item4_inventory_policy', 'item4_advisory_context',
        'vulnerability_exploitation_prerequisite', 'source_version_parser', 'item4_ox_benchmark',
        'item4_run_ledger', 'asset_vulntology', 'item4_questionnaire', 'prerequisite_llm',
        'identification_agents', 'precision_role_runtime', 'prerequisite_adapters', 'paths')


from src.common.paths import source_path

def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def sealed_json(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('Source fingerprint changed: ' + path.name)
    return json.loads(raw)


def input_packet(folder, manifest, cve):
    key = f'{PREFIX}/cves/{cve}.json'
    if folder.suffix == '.sqlite3' and folder.is_file():
        from src.item4.evaluation import frozen_evidence_packets as item4_frozen_packets
        raw = item4_frozen_packets.read(folder, cve)
        if sha(raw) != manifest[key]:
            raise ValueError('Staged scenario packet hash mismatch: ' + cve)
        packet = json.loads(raw)
    else:
        packet = sealed_json(folder / key, manifest[key])
    if packet['cve'] != cve or not packet['cases']:
        raise ValueError('Invalid frozen packet: ' + cve)
    return packet


def prepare_run(cves=None, *, cohort='v1', delivery=None, bulk=False, resume_id=None,
                backend_identity=None):
    if cohort not in {'v1', 'all'}:
        raise ValueError('Select v1 or all.')
    report = json.loads((REPLAY / 'report.json').read_bytes())
    base = json.loads(BASELINE.read_bytes())
    folder = Path(delivery or base['artifact_directory']).resolve()
    manifest = sealed_json(folder / 'delivery_manifest.json', report['source_manifest_sha256'])
    pop_key = PREFIX + '/population_ledger.json'
    population = sealed_json(folder / pop_key, manifest[pop_key])['cves']
    allowed = set(population)
    pins = {'v3 delivery manifest': report['source_manifest_sha256'], 'frozen CVE population': manifest[pop_key],
            'source layout': file_sha(ROOT/'src/layout.json')}
    if cohort == 'v1':
        raw = (REPLAY / 'cve_audit.jsonl').read_bytes()
        if sha(raw) != report['ledgers']['cve_audit.jsonl']:
            raise ValueError('The V1 rejection cohort failed its integrity check.')
        allowed = {row['cve'] for row in map(json.loads, raw.splitlines()) if row['prior_v1']}
        if len(allowed) != 3640 or not allowed.issubset(population):
            raise ValueError('Invalid original V1 cohort.')
        pins['frozen V1 selection ledger'] = sha(raw)
    selected = sorted(allowed) if cves is None else list(cves)
    if (not selected or not all(isinstance(cve, str) and re.fullmatch(r'CVE-\d{4}-\d{4,}', cve)
                                for cve in selected) or len(set(selected)) != len(selected)
            or not set(selected).issubset(allowed)):
        raise ValueError('Select unique CVEs belonging to the requested frozen cohort.')
    if bulk:
        from src.item4.evaluation import frozen_evidence_packets as item4_frozen_packets
        folder = item4_frozen_packets.stage(folder, manifest, base['archive']['sha256'], population)
    seen = set()
    selected_pins = {}
    for cve in selected:
        packet = input_packet(folder, manifest, cve)
        cases = packet['cases']
        ids = {r['id'] for r in cases}
        if len(ids) != len(cases) or seen.intersection(ids) or any(r['cve'] != cve for r in cases):
            raise ValueError('Duplicate or out-of-scope scenario IDs.')
        seen.update(ids)
        selected_pins[cve] = manifest[f'{PREFIX}/cves/{cve}.json']
    pins['selected input packets'] = sha(json.dumps(selected_pins, sort_keys=True).encode())
    if bulk:
        pins['selected case IDs'] = sha(json.dumps(sorted(seen), separators=(',', ':')).encode())
        if cves is None and cohort == 'all' and (len(selected), len(seen)) != (base['population_cves'], base['cases']):
            raise ValueError('Whole-population scenario coverage does not match the verified baseline.')
    for name in ('cisa_reference_manifest.json', 'cisa_advisories.json'):
        pins[name] = file_sha(ROOT / 'data' / name)
    for year in sorted({c.split('-')[1] for c in selected}):
        name = f'records_{year}.json'
        pins[name] = sha((asset_vulntology.DATA / name).read_bytes())
    identity = prerequisite_llm.identity('operating-record-review')
    hosted = identity.get('provider') == 'typesafe_jev'
    models = dict(identity.get('base_files_sha256') or {})
    if hosted:
        import os
        if not os.getenv('TYPESAFE_API_KEY'):
            raise ValueError('TYPESAFE_API_KEY is required for a Jev evaluation run.')
        if backend_identity is not None:
            raise ValueError('Jev cannot be combined with an H200 backend.')
        # Hosted weights cannot be fingerprinted. Pin the declared model and local
        # decision policy explicitly, without claiming this is a weights hash.
        models['hosted model and decision policy (not weights)'] = item4_scenario_moe.digest(identity)
    if not models:
        raise ValueError('This evaluation requires fingerprinted model weights.')
    if identity.get('adapter'):
        models['operating-record-review adapter'] = identity['adapter']['sha256']
    files = CODE + (('item4_frozen_packets', 'item4_moe_batch', 'item4_bulk_run', 'item4_vex_assessment',
                     'candidate_advisories', 'cpe23', 'llm_output_schema', 'model_paths') if bulk else ())
    code = {name + '.py': sha((source_path(name + '.py', root=ROOT)).read_bytes()) for name in files}
    if hosted:
        code['src/item4/models/constrained_choice_provider.py'] = file_sha(ROOT/'src/item4/models/constrained_choice_provider.py')
    code['src/__init__.py'] = file_sha(ROOT/'src/__init__.py')
    for command_source in ('tools/__init__.py','tools/common/paths.py'):
        code[command_source] = file_sha(ROOT/command_source)
    pins['command layout'] = file_sha(ROOT/'tools/layout.json')
    method = 'scenario_moe_local_llm'
    if hosted:
        method = 'scenario_moe_typesafe_jev'
    if bulk:
        code['tools/item4/run_item4_scenario_moe.py'] = file_sha(ROOT / 'tools/item4/run_item4_scenario_moe.py')
    if backend_identity is not None:
        if (backend_identity['base_files_sha256'] != identity['base_files_sha256']
                or backend_identity.get('role_adapter') != identity.get('adapter')
                or backend_identity['moe_version'] != item4_scenario_moe.VERSION):
            raise ValueError('The GPU worker differs from the pinned local v2 runtime.')
        code.update(backend_identity['runtime_sha256'])
        models.update(backend_identity['tokenizer_sha256'])
        code['GPU runtime identity'] = sha(json.dumps(backend_identity, sort_keys=True).encode())
        method = 'scenario_moe_h200_llm'
    settings = dict(generation_method=method, total=len(seen),
                    code_hashes=code, model_hashes=models, data_hashes=pins)
    if resume_id:
        row = ledger.resume_run(resume_id, **settings)
        return row, (folder, manifest, selected, cohort)
    rid = 'moe-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12]
    row = ledger.start_run(rid, **settings, resumable=True) if bulk else ledger.start_run(rid, **settings)
    return row, (folder, manifest, selected, cohort)


def condition_rule(detail, questions, product):
    """Bind an unambiguous source expression to observable, independently quoted questions."""
    if not questions or product['state'] != 'known_affected':
        return None
    sources = {s['id']: s for s in detail['sources']}
    rows = [e for e in product['evidence'] if e['status'] == 'known_affected' and e['version_membership'] == 'true']
    eligible = [s for s in detail['scenarios'] if not s.get('scope_ambiguous') and
                any(r['product_key'] in s.get('product_keys', []) for r in rows)]
    questions = [q for q in questions if q.get('cve') == detail['cve']
                 and q.get('component_ref') == product['component_ref']]
    # The archived observation may correspond to only one of several supplier
    # scenarios for the product. An unobserved alternative cannot clear the product.
    matches = []
    for source_rule in eligible:
        bound = _bind_rule(source_rule, questions, rows, sources)
        if bound:
            matches.append(bound)
    return matches[0] if len(matches) == 1 else None


def _bind_rule(source_rule, questions, rows, sources):
    bindings, _ = source_bindings(questions, {'selected_path': source_rule})
    atoms = []
    for atom in source_rule['conditions']:
        ref = atom['source_ref']
        source = sources.get(ref['source_id'])
        if not atom.get('operator_observable') or not source or atom['id'] not in bindings or source.get('subject_ambiguous'):
            return None
        a, b = ref['span']
        if (not ref['quote'] or not 0 <= a < b <= len(source['text']) or source['text'][a:b] != ref['quote']
                or sha(source['text'].encode()) != source['text_sha256']):
            return None
        matching = [r for r in rows if r['product_key'] in source_rule['product_keys']
                    and r['product_key'] in source['product_keys'] and r['document_sha256'] == source['document_sha256']
                    and source['id'] in r['source_ids']]
        if len(matching) != 1:
            return None
        atoms.append(dict(id=atom['id'], question_id=bindings[atom['id']], source_id=source['id'],
                          quote=ref['quote'], evidence_id=matching[0]['evidence_id']))
    return dict(expression=source_rule['expression'], conditions=atoms) if atoms else None


def scenario_input(case, product):
    inputs = {k: case[k] for k in ('id', 'cve', 'answers', 'context', 'synthetic')}
    inputs.update(component_ref=product['component_ref'], version=product['version'])
    return inputs


def bind_candidate(candidate, run_id, packet_hash, product, rule):
    candidate.update(run_id=run_id, packet_sha256=packet_hash, verified_product=product,
                     source_rule_identities=rule and [a['source_id'] for a in rule['conditions']])
    return candidate


def scoped_inputs(packet):
    cve = packet['cve']
    job = packet['job']
    components, declarations = item4_questionnaire.inventory(job['input_bom'])
    target = next((d for d in declarations if d['cve'] == cve), {})
    refs = target.get('component_refs', [])
    matches = [c for c in components if c['ref'] in refs]
    if len(refs) != 1 or len(matches) != 1:
        return dict(cve=cve, component_ref=None, version=None, state='unknown', evidence=[],
                    reasons=['scenario_component_scope_unresolved']), None
    product = item4_advisory_context.verified_version_evidence(cve, matches[0])
    rule = condition_rule(asset_vulntology.detail(cve), job['questions'], product)
    return product, rule


def execute_run(record, plan):
    run_id = record['run_id']
    directory = OUTPUT / run_id
    folder, manifest, selected, cohort = plan
    attempted = accepted = 0
    statuses, generations, experts = Counter(), Counter(), Counter()
    status = 'failed'
    error = None
    try:
        directory.mkdir(parents=True, exist_ok=False)
        with (directory / 'candidates.jsonl').open('x', encoding='utf-8') as stream:
            for cve in selected:
                packet = input_packet(folder, manifest, cve)
                product, rule = scoped_inputs(packet)
                cache = {}
                for case in packet['cases']:
                    inputs = scenario_input(case, product)
                    candidate = candidate_policy.generate_candidate(inputs, product, condition_rule=rule, cache=cache)
                    bind_candidate(candidate, run_id, manifest[f'{PREFIX}/cves/{cve}.json'], product, rule)
                    stream.write(json.dumps(candidate, ensure_ascii=False, separators=(',', ':')) + '\n')
                    stream.flush()
                    attempted += 1
                    complete = candidate['generation_status'] == 'completed'
                    accepted += int(complete)
                    generations[candidate['generation_status']] += 1
                    if complete:
                        statuses[candidate['candidate_status']] += 1
                    for expert in candidate['experts']:
                        experts[expert['execution']] += 1
                    ledger.update_run(run_id, completed=attempted, candidate_count=accepted)
        status = 'completed' if accepted == record['total'] else 'partial' if accepted else 'failed'
        if accepted != attempted:
            error = 'One or more scenario experts could not finish. See per-scenario traces.'
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)[:400]
        status = 'partial' if attempted else 'failed'
    counts = dict(cohort=cohort, selected_cves=selected, candidate_statuses=statuses, generation_statuses=generations,
                  expert_executions=experts, expert_validated=False, synthetic=True)
    path = directory / 'candidates.jsonl'
    result = None
    if path.is_file():
        counts['candidates_sha256'] = file_sha(path)
        result = {k: counts[k] for k in ('candidates_sha256', 'generation_statuses', 'candidate_statuses')}
    current = ledger.update_run(run_id, completed=attempted, candidate_count=accepted,
                                status=status, error=error, result=result)
    if directory.is_dir():
        report = directory / 'report.json'
        temp = report.with_suffix('.tmp')
        temp.write_text(json.dumps(dict(ledger=current, **counts), indent=2, ensure_ascii=False), encoding='utf-8')
        temp.replace(report)
    return current
