"""Compare raw agent/rule outputs on the frozen, single-component #3 evaluation BOMs."""

if __package__ in (None, ''):
    import sys as _bootstrap_sys
    from pathlib import Path as _BootstrapPath
    _bootstrap_sys.path.insert(0, str(_BootstrapPath(__file__).resolve().parents[2]))

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import zlib


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'results/item3_benchmark_validation_h200_20261119'
OUTPUT = ROOT / 'results/item3_paired_recall_20261121'
MODES = ('agents', 'rules')
ROLES = {'I1': 'p2', 'I2': 'p3', 'I3': 'p4'}


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def check(test, message):
    if not test:
        raise ValueError(message)


def mode_sets(row):
    return tuple({v['cve_id'] for v in row['cves'] if v['match_status'] == state}
                 for state in ('match', 'unknown'))


def view(row):
    validation = row['validation']
    stages = {}
    for name, key in ROLES.items():
        record = row[key]
        agent = record.get('agent') or {}
        stages[name] = dict(status=record['status'], model_status=agent.get('status'),
                            model_used=agent.get('llm_used', False),
                            guard_accepted=agent.get('guard_accepted'),
                            model_prediction=agent.get('prediction'),
                            model_packet_sha256=(agent.get('generation') or {}).get('model_packet_sha256'))
    stages['I1']['ordered_candidates'] = [r['candidate_id'] for r in row['p2']['candidates']]
    stages['I2'].update(comparison_version=row['p3'].get('comparison_version'),
                        comparison_basis=row['p3'].get('comparison_basis'),
                        conflicts=row['p3'].get('conflicts', []))
    stages['I3'].update(acceptance_rule=row['p4'].get('acceptance_rule'),
                        routing_reasons=row.get('routing', {}).get('decisions', {}).get('P4', {}).get('reasons', []))
    return dict(stages=stages, final={k: validation.get(k) for k in (
        'status', 'identity_status', 'version_status', 'selected_candidate_id',
        'part', 'vendor', 'product', 'acceptance_rule', 'reasons', 'evidence_refs')})


def trace_class(a, r):
    """Mutually exclusive observed decision paths, not a causal ablation."""
    reasons = set(a['final']['reasons'])
    name_gate = 'P2_agent_not_confirmed' in reasons or 'P2_candidate_not_ranked' in reasons
    id_gate = 'P4_agent_not_confirmed' in reasons
    if name_gate and id_gate:
        return 'I1_rank_and_I3_identifier_not_confirmed'
    if name_gate:
        return 'I1_rank_not_confirmed_by_final_gate'
    if id_gate and a['stages']['I3']['model_status'] == 'abstained':
        return 'I3_model_abstained_final_identifier_gate'
    if id_gate:
        return 'I3_identifier_not_confirmed'
    version_changed = (a['stages']['I2']['comparison_version'] != r['stages']['I2']['comparison_version']
                       or a['stages']['I2']['status'] != r['stages']['I2']['status'])
    id_changed = a['final']['identity_status'] != r['final']['identity_status']
    if version_changed and id_changed:
        return 'version_and_identity_decisions_differ'
    if version_changed:
        return 'version_decision_differs'
    if id_changed:
        return 'identity_evidence_gate_differs'
    return 'cause_unresolved'


def compare(source, target):
    dbfile = source / 'validation.sqlite3'
    manifest = json.loads((source / 'artifacts_manifest.json').read_bytes())
    dbhash = sha256(dbfile)
    check(dbhash == manifest['validation.sqlite3'], 'Frozen database hash differs from the delivery manifest')
    official = json.loads((source / 'precision_target_result.json').read_bytes())
    counts, cases, scenarios = Counter(), Counter(), defaultdict(Counter)
    by_class, by_product = defaultdict(Counter), defaultdict(Counter)
    missing_retrieval = Counter()
    modes = {m: Counter() for m in MODES}
    seen = set()
    total_changed = 0
    ledger_rows = 0
    sql = """SELECT c.gold_id, c.input_sha256, c.id, g.label, i.components, u.sha256, u.agents, u.rules, cr.payload
             FROM cases c JOIN gold g ON g.id=c.gold_id JOIN inputs i ON i.sha256=c.input_sha256
             JOIN input_units iu ON iu.input_sha256=c.input_sha256 JOIN units u ON u.sha256=iu.unit_sha256
             JOIN case_results cr ON cr.id=c.id ORDER BY c.gold_id"""
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target) as tmp:
        ledger = Path(tmp) / 'case_ledger.jsonl'
        db = sqlite3.connect(dbfile.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
        try:
            with ledger.open('w', encoding='utf-8', newline='\n') as out:
                for gid, input_id, filename, label, n, unit_id, packed_a, packed_r, saved in db.execute(sql):
                    check(n == 1 and gid not in seen, f'Unexpected component or duplicate BOM: {gid}')
                    seen.add(gid)
                    gold = json.loads(label)
                    summary = json.loads(saved)['modes']
                    rows = {}
                    matches, candidates = {}, {}
                    expected, unjudged = set(gold['expected_cves']), set(gold['unknown_cves'])
                    for mode, packed in zip(MODES, (packed_a, packed_r)):
                        raw = json.loads(zlib.decompress(packed))
                        check(not raw.get('error') and len(raw['components']) == 1, gid)
                        rows[mode] = row = raw['components'][0]
                        matched, possible = mode_sets(row)
                        matches[mode], candidates[mode] = matched, possible
                        saved_mode = summary[mode]
                        check(matched == set(saved_mode['confirmed_cves']) and
                              possible == set(saved_mode['candidate_cves']), f'Raw output differs from published sets: {gid}')
                        values = dict(TP=len(matched & expected), FP=len(matched - expected - unjudged),
                                      FN=len(expected - matched), unjudged=len(matched & unjudged), out_of_scope=0)
                        # This particular frozen run reports zero out-of-scope and unjudged positives.
                        # Reject another cohort rather than silently treating those positives as FP.
                        check(not values['unjudged'] and values == saved_mode['gold_score']['mapping'], gid)
                        modes[mode].update(values)
                    check(rows['agents']['component'] == rows['rules']['component'], gid)
                    a, r = matches['agents'], matches['rules']
                    edges = dict(both_tp=a & r & expected, both_fn=expected - a - r,
                                 rules_only_tp=(r-a) & expected, agents_only_tp=(a-r) & expected,
                                 both_fp=(a & r)-expected, rules_only_fp=(r-a)-expected,
                                 agents_only_fp=(a-r)-expected)
                    for group, ids in edges.items():
                        counts[group] += len(ids)
                        cases[group] += bool(ids)
                        scenarios[gold['scenario']][group] += len(ids)
                    if a == r and not edges['both_fn']:
                        continue
                    ledger_rows += 1
                    traces = {m: view(rows[m]) for m in MODES}
                    cause = trace_class(traces['agents'], traces['rules']) if a != r else None
                    if a != r:
                        total_changed += 1
                        by_class[cause]['changed_BOMs'] += 1
                        for group in ('rules_only_tp','agents_only_tp','rules_only_fp','agents_only_fp'):
                            by_class[cause][group] += len(edges[group])
                        fields = gold['gold']['canonical_fields']
                        by_product[f'{fields[1]}:{fields[2]}']['rules_only_tp'] += len(edges['rules_only_tp'])
                        by_product[f'{fields[1]}:{fields[2]}']['agents_only_tp'] += len(edges['agents_only_tp'])
                    for name, other in (('rules_only_tp','agents'), ('agents_only_tp','rules')):
                        missing_retrieval[name+'_other_mode_candidate'] += len(edges[name] & candidates[other])
                        missing_retrieval[name+'_other_mode_absent'] += len(edges[name] - candidates[other])
                    audit = dict(gold_id=gid, sbom_file=filename, input_sha256=input_id, unit_sha256=unit_id,
                                 component_id=rows['agents']['component']['id'], scenario=gold['scenario'],
                                 control_sbom_id=gold['control_sbom_id'], source_condition_id=gold['condition_id'],
                                 expected_vendor_product=gold['gold']['canonical_fields'][1:3],
                                 trace_class=cause, edges={k: sorted(v) for k,v in edges.items()},
                                 candidate_only={m: sorted(candidates[m]-matches[m]) for m in MODES},
                                 traces=traces)
                    out.write(json.dumps(audit, ensure_ascii=False, separators=(',', ':'))+'\n')
            gold_count, = db.execute('SELECT COUNT(*) FROM gold').fetchone()
            check(len(seen) == gold_count == official['completed_cases'], 'Gold population mismatch')
        finally:
            db.close()
        for mode, truth in [('agents',official['counts']), ('rules',official['rules_baseline']['counts'])]:
            check(modes[mode] == Counter(truth), f'Official {mode} totals not reproduced')
        report = dict(cases=len(seen), components_per_case=1, changed_confirmed_set_cases=total_changed,
                      ledger_cases=ledger_rows, mode_totals=modes, paired_edges=counts,
                      cases_with_each_edge_type=cases, differing_decisions_by_trace_class=by_class,
                      missed_by_other_mode=missing_retrieval, by_benchmark_scenario=scenarios,
                      by_expected_product={k: v for k,v in sorted(by_product.items(), key=lambda p:-p[1]['rules_only_tp'])},
                      source_run=source.name, source_database_sha256=dbhash,
                      frozen_gold_input_fingerprint=official['dataset']['frozen_fingerprint_sha256'],
                      source_score_verified_per_case=True, ledger_sha256=sha256(ledger),
                      ledger_selection='Any one-sided confirmed mapping or a known positive missed by both modes. One JSON object per BOM.',
                      interpretation='Case-CVE positive edges on frozen synthetic source-derived gold. I1/P2 name ranking, I2/P3 version, I3/P4 identifier. Classes describe stored validation reasons and decisions, without proving counterfactual causation. Candidate-only CVEs were not counted as confirmations.')
        result = Path(tmp) / 'report.json'
        result.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
        ledger.replace(target / ledger.name)
        result.replace(target / result.name)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    report = compare(args.source, args.output)
    print(json.dumps({k:report[k] for k in ('cases','paired_edges','differing_decisions_by_trace_class','missed_by_other_mode')}))
