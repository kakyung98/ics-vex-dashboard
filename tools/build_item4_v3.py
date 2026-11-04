"""Migrate #4 inputs to CWE-first contracts; never invent adjudicated labels."""
from pathlib import Path
import sys
import json
import hashlib
from collections import Counter
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.vex_routing import classify, policy
from src.cwe_taxonomy import load
from src.cve_source_evidence import catalog

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build():
    source = ROOT / 'data/operational_review_benchmark_v2'
    target = ROOT / 'data/item4_v3'
    target.mkdir(exist_ok=True)
    counts = {}; routing = {}; role_counts = {}; source_hashes = {}
    groups = {}; all_ids = set()
    for split in ('train', 'validation', 'test'):
        path = source / (split + '.annotation.jsonl')
        source_hashes[str(path.relative_to(ROOT))] = sha(path)
        inputs = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        records = []; scenarios = []; roles = {r: [] for r in ('routing', 'extraction', 'source_analysis', 'questions', 'assessment', 'authoring')}
        groups[split] = {row['group_id'] for row in inputs}
        for row in inputs:
            assert row['cve'] not in all_ids
            all_ids.add(row['cve'])
            case = {**row, 'routing_sources': catalog(row['cve'], row['description'])}
            route = classify(case)
            record = {**row, 'schema': 'ics-vex-item4-case/3', 'analysis_route_prediction': route,
                      'routing_gold': None, 'required_conditions': None, 'function_targets': None,
                      'reference_questions': {'common': None, 'specific': None},
                      'operational_scenarios': [], 'reference_vex': None,
                      'operator_answerability': {'status': 'pending', 'reviewers': []},
                      'review_status': 'pending_independent_annotation', 'reviewers': [], 'adjudicator': None,
                      'source_material': {'collected_directory': (ROOT / 'data/source_snapshots' / row['cve']).is_dir(),
                                          'complete_build_scope_verified': False},
                      'evidence_catalog': case['routing_sources'],
                      'annotation_note': 'Policy routing predictions and structural expectations are not independent gold. Annotators verify routing, exact evidence, operator answerability and scoped VEX separately.'}
            records.append(record)
            key = {'case_id': row['id'], 'cve': row['cve'], 'split': split, 'group_id': row['group_id'],
                   'target': None, 'status': 'pending_independent_annotation', 'train_ready': False}
            roles['routing'].append({**key, 'policy_prediction': route['requirement']})
            requirement = route['requirement']
            variants = [('routing_unresolved', False)]
            if requirement == 'source_required':
                variants = [('required_source_missing', False), ('required_source_supplied', True)]
                roles['source_analysis'].append({**key, 'requires_complete_build_and_target_mapping': True})
                roles['extraction'].append({**key, 'branch': 'source_required'})
            elif requirement == 'operational_review':
                variants = [('operator_review', False)]
                roles['questions'].append({**key, 'required_scopes': ['common', 'specific'], 'operator_answerable': True})
                roles['assessment'].append({**key, 'operator_facts': None, 'unknown_is_not_yes': True})
                roles['extraction'].append({**key, 'branch': 'operational_review'})
            for variant, available in variants:
                scenario = {**key, 'id': row['id'] + ':' + variant, 'variant': variant,
                            'source_available': available, 'source_availability_is_simulated': True,
                            'actual_source_artifact': None, 'operator_facts': None,
                            'policy_expected_status': 'under_investigation' if variant in {'required_source_missing', 'routing_unresolved'} else None,
                            'expectation_kind': 'control_flow_policy_only_not_exploitability_gold',
                            'reference_status': None}
                scenarios.append(scenario)
                roles['authoring'].append({**key, 'scenario_id': scenario['id'], 'locked_decision': None,
                                           'applicability': 'after_branch_evidence_or_code_only_deferral',
                                           'runtime_missing_source_policy': 'code_only_no_LLM'})
        def write(name, rows):
            (target / name).write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
        write(split + '.cases.jsonl', records)
        write(split + '.scenarios.jsonl', scenarios)
        for role, rows in roles.items():
            write(split + '.' + role + '.annotation.jsonl', rows)
        counts[split] = {'unique_cves': len(records), 'structural_scenarios': len(scenarios)}
        routing[split] = dict(Counter(r['analysis_route_prediction']['requirement'] for r in records))
        role_counts[split] = {r: len(rows) for r, rows in roles.items()}
    assert not any(groups[a] & groups[b] for a, b in [('train', 'validation'), ('train', 'test'), ('validation', 'test')])
    legacy = []
    for directory in ('data/source_training_sw', 'data/grounded_role_sft_v1', 'data/operational_review_benchmark_v2'):
        for path in sorted((ROOT / directory).rglob('*manifest*.json')):
            legacy.append({'path': str(path.relative_to(ROOT)).replace('\\', '/'), 'sha256': sha(path),
                           'status': 'legacy_not_qualified_for_CWE_first_contract',
                           'retained': True, 'used_as_independent_gold': False})
    manifest = {'schema': 'ics-vex-item4-dataset/3', 'status': 'awaiting_independent_annotation',
                'counts': counts, 'routing_policy_predictions': routing, 'role_annotation_counts': role_counts,
                'independent_gold_count': 0, 'train_ready_count': 0, 'training_started': False,
                'taxonomy': {k: load().get(k) for k in ('version', 'xml_sha256')},
                'routing_policy_version': policy()['version'], 'routing_policy_sha256': policy()['sha256'],
                'inherited_split_manifest': str((source / 'manifest.json').relative_to(ROOT)).replace('\\', '/'),
                'cross_split_group_overlap': 0, 'product_family_disjoint': False,
                'split_policy': 'All role rows and scenarios inherit the original CVE group split. No reference labels copied.',
                'source_input_hashes': source_hashes, 'legacy_artifacts': legacy,
                'files': {p.name: sha(p) for p in sorted(target.glob('*.jsonl'))},
                'limitations': ['Routing predictions require independent adjudication.',
                               'Simulated source availability does not assert a complete source artifact exists.',
                               'Old program build tests and synthetic LLM targets are not CVE exploitability ground truth.',
                               'No old #4 weights are qualified for the new common/specific operator question contract.']}
    (target / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: manifest[k] for k in ('counts', 'routing_policy_predictions', 'role_annotation_counts', 'independent_gold_count')}, indent=2))


if __name__ == '__main__':
    build()
